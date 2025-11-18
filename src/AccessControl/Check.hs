{-# language DataKinds #-}
{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes #-}
{-# language MultiWayIf #-}
module AccessControl.Check where

import AccessControl.Relation
import AccessControl.Schema
import AccessControl.Validate (RelPerm(..), mkDefMap)
import Data.Time.Clock.POSIX (POSIXTime)
import           Data.Map (Map)
import qualified Data.Map as Map
import Data.Data (Data)
import Data.Either (partitionEithers)
import Data.List (partition)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import           Data.Map (Map)
import Data.Maybe (mapMaybe)
import Data.SafeCopy (SafeCopy)
import           Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import Data.Typeable (Typeable)
import Data.Void (Void)
import Debug.Trace (trace)
import GHC.Generics
import Text.PrettyPrint.HughesPJ (Doc, (<+>), ($$), ($+$))
import qualified Text.PrettyPrint.HughesPJ as PP

debugTrace = trace
-- debugTrace = const id



data Access
  = Allowed
  | NotAllowed [Text]
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

instance SafeCopy Access

instance Semigroup Access where
  Allowed <> _       = Allowed
  _       <> Allowed = Allowed
  (NotAllowed l) <> (NotAllowed r) = NotAllowed (l ++ r)

instance Monoid Access where
  mempty = NotAllowed []

isAllowed :: Access -> Bool
isAllowed Allowed = True
isAllowed _       = False

filterExpired :: Maybe POSIXTime -> [ RelationTuple ] -> [ RelationTuple ]
filterExpired mNow relationTuples = filter notExpired relationTuples
  where
    notExpired :: RelationTuple -> Bool
    notExpired rt = case expiration rt of
      Nothing -> True
      (Just expires) ->
        case mNow of
          Nothing    -> False
          (Just now) -> expires > (posixTimeToExpiration now)

{-
As an alternative implementation -- could we have a lazy function which expands the permission tree, and then a second function which just searches that tree.

The expansion function seems useful for diagnostic purposes.

If a RelationTuple has caveats such as an expiration then the relations it matches against in the schema must also have those caveats.

For example, if we have:

    relation reader: user

And a RelationTuple:


    document:somedocument#reader@user:sean[expiration:2022-12-31T23:59:59Z]


That RelationTuple will not match because it has an expiration date, but the relation only matches relation tuples that do not have an expiration. Instead we need the schema:

    relation reader: user | user with expiration

Now the relation can match with users that do or do not have an expiration time. If we have:

    relation reader: user with expiration

Then all reader relations must have an expiration to match.


-- FIXME:

The current implementation does not seem to validate against the schema (aka, rsDefMap). That is problematic for sure.

I think it means that you can insert arbitrary RelationTuples that grant a subject permission to a resource even if the schema does not actually allow it.

The schema is basically the type system.

This suggests that relation tuples can only be inserted if they match the schema, and also, the schema can only be modified in ways that do not cause any existing relation tuples to become invalid.

-}
check :: Map Text RelPerm
      -> [ RelationTuple ]
      -> Object NoWildcard  -- ^ resource
      -> Permission         -- ^ permission
      -> Object NoWildcard  -- ^ subject
      -> Maybe POSIXTime
      -> Access
check rsDefMap rsTuples resource@(Object (ObjectType resourceTy) _) (Permission perm) subject@(Object (ObjectType subjectType) _) now =
  debugTrace ("## check - " ++ show (ppObject resource, perm, ppObject subject)) $
  -- find the subset of RelationTuples which are relevant to the requested 'Resource'
  case filter (\(RelationTuple resource' _ _ _ _ _) -> resource == resource') rsTuples of
    [] -> debugTrace ("## rsTuples = " ++ show (ppRelationTuples rsTuples)) $
          NotAllowed [ "no tuples for resource located - resource: "  <> (T.pack $ show $ ppObject resource) ]
    relationTuples ->
      -- find the object definition that is relevant to the 'resourceType'
      case Map.lookup resourceTy rsDefMap of
           Nothing -> NotAllowed [ "object not found in definitions - " <> resourceTy ]
           (Just (RelPerm rm pm)) ->
             -- find the requested permission
             case Map.lookup perm pm of
               -- fixme: perm could also be a relation not actually a permission
               Nothing -> NotAllowed [ "permission " <> perm <> " not defined for resource " <> resourceTy ]
               (Just expr) -> checkExpr (filterExpired now relationTuples) expr rm
  where
    subjectIdMatch :: ObjectId -> WildcardObjectId -> Bool
    subjectIdMatch _ Wildcard = True
    subjectIdMatch (ObjectId a) (Specific (ObjectId b)) = a == b
--    subjectIdMatch a b = error $ "subjectIdMatch " ++ show (a,b)

    isMatch :: Object NoWildcard -> Relation -> Object NoWildcard -> RelationTuple -> Bool
    isMatch resourceA relationA (Object subjectTypeA subjectIdA) (RelationTuple resourceB relationB (Object subjectTypeB subjectIdB) Nothing _mTag _mExpiration) =
      (resourceA == resourceB) && (relationA == relationB) && (subjectTypeA == subjectTypeB) && (subjectIdMatch subjectIdA subjectIdB)

    checkExpr :: [ RelationTuple ]
              -> PermissionExpression
              -> Map Text (NonEmpty TypeReference)
              -> Access
    -- handle a simple reference
--    checkExpr relationTuples (Ref tr@(TypeReference (Resource relName Nothing) Nothing)) rm =
    checkExpr relationTuples (Rel (Relation relName)) rm =
      case Map.lookup relName rm of
        Nothing  -> NotAllowed [ "permission  " <> perm <> " refers to a relation " <> relName <> " which can not be found." ]
        (Just subjectTypes) ->
          debugTrace ("\nSubjectTypes -> " ++ show (NonEmpty.map ppTypeReference subjectTypes) ++ "\n\nnSubject ->\n" ++ show (ppObject subject) ++ "\n\nrel -> " ++ (T.unpack relName) ++ "\n\nnRelationTypes ->\n" ++ show (ppRelationTuples relationTuples) ++ "\n\nresource -> " ++ show (ppObject resource)) $
          let (direct, others) = partition (hasSubjectType (ObjectType subjectType)) relationTuples
          in if |  any (isMatch resource (Relation relName) subject) direct -> Allowed
                | otherwise ->
                    let checkOthers reasons [] = NotAllowed reasons
                        -- why would the following case happen?
                        checkOthers oldReasons ((RelationTuple res perm subj Nothing _mTag _mExpiration) : os) =
                          debugTrace "not sure why we are seeing this checkOthers case" $ checkOthers oldReasons os
                        checkOthers oldReasons ((RelationTuple res perm subj@(Object _ Wildcard) (Just (Relation subRelation)) _mTag _mExpiration):os) =
                          debugTrace "not sure how to handle wilcards here" $ checkOthers oldReasons os
                        checkOthers oldReasons ((RelationTuple res perm subj@(Object ot (Specific oi))  (Just (Relation subRelation)) _mTag _mExpiration):os) =
                          case check rsDefMap rsTuples (Object ot oi) (Permission subRelation) subject now of
                            Allowed -> Allowed
                            (NotAllowed reasons) -> checkOthers (oldReasons ++ reasons) os
                    in checkOthers [] others

    checkExpr relationTuples p@(Union l r) rm =
      debugTrace ("\ncheckExpr - " ++ (show $ ppPermissionExpression p) ++ "\n") $
      case checkExpr relationTuples l rm of
        Allowed -> Allowed
        NotAllowed nal ->
          case checkExpr relationTuples r rm of
            Allowed -> Allowed
            (NotAllowed nar) -> NotAllowed $ (map  (\s -> "Union - left - " <> s) nal) ++ (map (\s -> "Union - right - " <> s) nar)
    checkExpr relationTuples (Arrow (Relation arrowRel) permOrRel) rm =
      debugTrace ("\ncheckExpr - Arrow\n") $
      case Map.lookup arrowRel rm of
        Nothing  -> NotAllowed [ "permission  " <> perm <> " refers to a relation " <> arrowRel <> " which can not be found." ]
        (Just subjectTypes) ->
          debugTrace ("checkExpr Arrow - \nSubjectTypes -> " ++ show ({- NonEmpty.map ppTypeReference -} subjectTypes) ++ "\n" ++ show arrowRel) $
          case subjectTypes of
            (st  :| sts) ->
--              let subjs = lookupSubjectsWithType relationTuples resource (Relation arrowRel) (ObjectType $ resourceType $ objectResource st)
              let subjs' = lookupSubjectsWithType relationTuples resource (Relation arrowRel) (ObjectType $ referenceType st)
                  subjs = mapMaybe toNoWildcard subjs'
              in debugTrace ("subjs - " ++ show subjs ++ " permOrRel - " ++ T.unpack permOrRel  ) $
                 -- fixme: this check could be done in parallel
                 -- fixme: does it makes since to pass extraTuples here? or should they have already been filtered out?
                 mconcat $ map (\subj -> check rsDefMap rsTuples subj (Permission permOrRel) subject now) subjs

lookupSubjects :: [ RelationTuple ] -> Object NoWildcard -> Relation -> [ Object AllowWildcard ]
lookupSubjects tuples res rel =
  [ subj | (RelationTuple res' rel' subj mSubRelation _mTag _mExpiration) <- tuples, res == res', rel == rel' ]

lookupSubjectsWithType :: [RelationTuple] -> Object NoWildcard -> Relation -> ObjectType -> [ Object AllowWildcard ]
lookupSubjectsWithType tuples res rel objectType =
  [ subj | (RelationTuple res' rel' subj@(Object objectType' _) mSubRelation _mTag _mExpiration) <- tuples, res == res', rel == rel', objectType == objectType' ]

{-
-- * Permission Tree

data SubjectReference = SubjectReference
  { subjectObject  :: Object SubjectK
  , subjectRelation :: Maybe Relation
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data SubjectOperation
  = SubjectUnion
  | SubjectIntersection
  | SubjectExclusion
    deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data AlgebraicSubjectSet = AlgebraicSubjectSet
  { asOperation      :: SubjectOperation
  , asPermissionTree :: PermissionTree
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data PermissionTree = PermissionTree
  { expandedObject   :: Object k
  , expandedRelation :: Either Relation Permission
  , expandedSubject  :: Either (Set SubjectReference) ()
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)


-- find the permission tree for all the subjects of a resource
expandPermissionTree :: RelationState -> Object -> Either Relation Permission -> PermissionTree
expandPermissionTree rs resource relOrPerm =
  case relOrPerm of
    (Left rel) ->
      PermissionTree { expandedObject   = resource
                     , expandedRelation = relOrPerm
                     , expandedSubject  = Left (Set.empty)
                     }

-}
