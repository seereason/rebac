{-# language DataKinds #-}
{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes #-}
{-# language MultiWayIf #-}
module AccessControl.Check where

import AccessControl.Relation
import AccessControl.Schema
import AccessControl.TupleIndex (TupleIndex, resourcesOfType, tuplesFor)
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
import Data.Maybe (isNothing, mapMaybe)
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

-- debugTrace = trace
debugTrace = const id

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
check defMap tuples = checkOnPath Set.empty defMap (\res -> filter ((== res) . resource) tuples)

-- | 'check' with the tuples in a 'TupleIndex', which finds a resource's
-- tuples without looking at all of them.  Building an index costs several
-- list scans, so this pays off when the index is kept, for instance
-- alongside the tuples in the stored state, rather than built per check.
checkIndexed :: Map Text RelPerm
             -> TupleIndex
             -> Object NoWildcard  -- ^ resource
             -> Permission         -- ^ permission
             -> Object NoWildcard  -- ^ subject
             -> Maybe POSIXTime
             -> Access
checkIndexed defMap idx = checkOnPath Set.empty defMap (\res -> tuplesFor res idx)

-- | The resources of a type on which the subject has a permission (or
-- relation), in the index's order: SpiceDB's LookupResources, which answers
-- questions like "which reports can this user view".
--
-- This version checks each resource of the type that has tuples.  That is
-- correct by construction, since 'checkIndexed' never allows anything on a
-- resource with no tuples, but it costs a check per resource of the type.
lookupResources :: Map Text RelPerm
                -> TupleIndex
                -> ObjectType         -- ^ the type of resource to look for
                -> Permission         -- ^ permission
                -> Object NoWildcard  -- ^ subject
                -> Maybe POSIXTime
                -> [ Object NoWildcard ]
lookupResources defMap idx ty perm subject now =
  [ res | res <- resourcesOfType ty idx, isAllowed (checkIndexed defMap idx res perm subject now) ]

-- | 'check', carrying the @(resource, permission)@ pairs that are being
-- evaluated further up the recursion for this same subject.
--
-- Reaching one of those pairs again means a cycle in the tuples, such as two
-- groups that are members of each other.  Going round the cycle cannot find
-- anything the evaluation further up is not already looking for, so that
-- branch is 'NotAllowed'.  Only the current path is kept, not everything
-- visited, so the same pair can still be reached by more than one route.
--
-- @tuplesOf@ gives the tuples whose resource is the one given; 'check' and
-- 'checkIndexed' differ only in how they find them.
checkOnPath :: Set (Object NoWildcard, Text)
            -> Map Text RelPerm
            -> (Object NoWildcard -> [ RelationTuple ])  -- ^ tuplesOf
            -> Object NoWildcard  -- ^ resource
            -> Permission         -- ^ permission
            -> Object NoWildcard  -- ^ subject
            -> Maybe POSIXTime
            -> Access
checkOnPath path rsDefMap tuplesOf resource@(Object (ObjectType resourceTy) _) (Permission perm) subject now
  | Set.member (resource, perm) path =
      NotAllowed [ "cycle - " <> perm <> " on " <> (T.pack $ show $ ppObject resource) <> " is already being checked" ]
  | otherwise =
  debugTrace ("## check - " ++ show (ppObject resource, perm, ppObject subject)) $
  -- find the subset of RelationTuples which are relevant to the requested 'Resource'
  case tuplesOf resource of
    [] -> NotAllowed [ "no tuples for resource located - resource: "  <> (T.pack $ show $ ppObject resource) ]
    relationTuples ->
      -- find the object definition that is relevant to the 'resourceType'
      case Map.lookup resourceTy rsDefMap of
           Nothing -> NotAllowed [ "object not found in definitions - " <> resourceTy ]
           (Just (RelPerm rm pm)) ->
             -- the name may be a permission or a relation, as it may in a
             -- subject set (@type#name@) or at the end of an arrow (@rel->name@)
             case Map.lookup perm pm of
               (Just expr) -> checkExpr (filterExpired now relationTuples) expr rm
               Nothing
                 | Map.member perm rm -> checkExpr (filterExpired now relationTuples) (Rel (Relation perm)) rm
                 | otherwise -> NotAllowed [ "permission or relation " <> perm <> " not defined for resource " <> resourceTy ]
  where
    -- the path for anything this evaluation recurses into
    path' = Set.insert (resource, perm) path

    subjectIdMatch :: ObjectId -> WildcardObjectId -> Bool
    subjectIdMatch _ Wildcard = True
    subjectIdMatch (ObjectId a) (Specific (ObjectId b)) = a == b
--    subjectIdMatch a b = error $ "subjectIdMatch " ++ show (a,b)

    -- | does a tuple with no subject relation name this subject, directly or by wildcard?
    --
    -- The caller has already narrowed the tuples to the right resource and relation.
    isDirectMatch :: Object NoWildcard -> RelationTuple -> Bool
    isDirectMatch (Object subjectTypeA subjectIdA) (RelationTuple _ _ (Object subjectTypeB subjectIdB) _ _ _) =
      (subjectTypeA == subjectTypeB) && (subjectIdMatch subjectIdA subjectIdB)

    -- | does the subject have the subject relation of any of these subject set tuples,
    -- e.g. for @page:1#viewer\@usergroup:x#member@, is the subject a member of @usergroup:x@?
    checkSubjectSets :: [Text] -> [ RelationTuple ] -> Access
    checkSubjectSets reasons [] = NotAllowed reasons
    checkSubjectSets reasons ((RelationTuple _ _ (Object ot (Specific oi)) (Just (Relation subRelation)) _mTag _mExpiration) : rts) =
      case checkOnPath path' rsDefMap tuplesOf (Object ot oi) (Permission subRelation) subject now of
        Allowed              -> Allowed
        (NotAllowed reasons') -> checkSubjectSets (reasons ++ reasons') rts
    -- a wildcard subject set, @type:*#rel@, is not valid and grants nothing
    checkSubjectSets reasons (_ : rts) = checkSubjectSets reasons rts

    checkExpr :: [ RelationTuple ]
              -> PermissionExpression
              -> Map Text (NonEmpty TypeReference)
              -> Access
    -- handle a simple reference
--    checkExpr relationTuples (Ref tr@(TypeReference (Resource relName Nothing) Nothing)) rm =
    checkExpr relationTuples (Rel (Relation relName)) rm =
      case Map.lookup relName rm of
        -- not a relation, so it should be another permission of this
        -- resource; checkOnPath evaluates it, or reports that it is neither
        Nothing  -> checkOnPath path' rsDefMap tuplesOf resource (Permission relName) subject now
        (Just subjectTypes) ->
          debugTrace ("\nSubjectTypes -> " ++ show (NonEmpty.map ppTypeReference subjectTypes) ++ "\n\nnSubject ->\n" ++ show (ppObject subject) ++ "\n\nrel -> " ++ (T.unpack relName) ++ "\n\nnRelationTypes ->\n" ++ show (ppRelationTuples relationTuples) ++ "\n\nresource -> " ++ show (ppObject resource)) $
          -- only the tuples of this relation count; a subject set on some
          -- other relation of the resource must not grant this one
          let (direct, subjectSets) = partition (isNothing . subjectRelation) (filter ((== Relation relName) . relation) relationTuples)
          in if | any (isDirectMatch subject) direct -> Allowed
                | otherwise -> checkSubjectSets [] subjectSets

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
                 mconcat $ map (\subj -> checkOnPath path' rsDefMap tuplesOf subj (Permission permOrRel) subject now) subjs

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
