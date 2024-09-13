{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes #-}
module AccessControl.Check where

import AccessControl.Relation
import AccessControl.Schema
import           Data.Map (Map)
import qualified Data.Map as Map
import Data.Data (Data)
import Data.Either (partitionEithers)
import Data.List (partition)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
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

data RelPerm = RelPerm
  { relMap  :: Map Text (NonEmpty TypeReference)
  , permMap :: Map Text PermissionExpression
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

ppRelMap :: Map Text (NonEmpty TypeReference) -> Doc
ppRelMap m =
  PP.vcat $ map ppRel (Map.toList m)
  where
    ppRel (nm,r) = PP.text "relation" <+> (ppText nm <> PP.char ':') <+> ppTypeReferences r

ppPermMap :: Map Text PermissionExpression -> Doc
ppPermMap m =
  PP.vcat $ map ppPerm (Map.toList m)
  where
    ppPerm (nm, p) = PP.text "permission" <+> ppText nm <+> PP.char '=' <+> ppPermissionExpression p

ppRelPerm :: RelPerm -> Doc
ppRelPerm (RelPerm r p) =
  ppRelMap r $+$ ppPermMap p

data RelationState = RelationState
  { rsTuples      :: [RelationTuple]
  , rsDefMap      :: Map Text RelPerm
  , rsSchema      :: Schema
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

mkRelationState :: Schema -> [RelationTuple] -> RelationState
mkRelationState s@(Schema defs) tuples =
  RelationState { rsTuples      = tuples
                , rsDefMap      = mkDefMap defs
                , rsSchema      = s
                }

mkDefMap
  :: [Definition]
  -> Map Text RelPerm
mkDefMap defs = Map.fromList $ map mkDefMapItem defs
 where
   mkDefMapItem (Definition nm decls) =
      let (rels, perms) = partitionEithers decls
          relMap  = Map.fromList $ map (\(ObjectRelation nm ot) -> (nm, ot)) rels
          permMap = Map.fromList $ map (\(ObjectPermission nm ex) -> (nm, ex)) perms
      in (nm, RelPerm relMap permMap)

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

{-
As an alternative implementation -- could we have a lazy function which expands the permission tree, and then a second function which just searches that tree.

The expansion function seems useful for diagnostic purposes.
-}
check' :: RelationState
       -> Object -- ^ resource
       -> Text   -- ^ permission
       -> Object -- ^ subject
       -> Access
check' rs@(RelationState rsTuples rsDefMap _) resource@(Object (ObjectType resourceTy) (ObjectId resourceId)) perm subject@(Object (ObjectType subjectType) (ObjectId subjectId)) =
  debugTrace ("## check - " ++ show (ppObject resource, perm, ppObject subject)) $
  -- find the subset of RelationTuples which are relevant to the requested 'Resource'
  case filter (\(RelationTuple resource' _ _ _) -> resource == resource') rsTuples of
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
               (Just expr) -> checkExpr relationTuples expr rm
  where
    checkExpr :: [ RelationTuple ]
              -> PermissionExpression
              -> Map Text (NonEmpty TypeReference)
              -> Access
    -- handle a simple reference
    checkExpr relationTuples (Ref tr@(TypeReference (Resource relName Nothing) Nothing)) rm =
      case Map.lookup relName rm of
        Nothing  -> NotAllowed [ "permission  " <> perm <> " refers to a relation " <> relName <> " which can not be found." ]
        (Just subjectTypes) ->
          debugTrace ("\nSubjectTypes -> " ++ show (NonEmpty.map ppTypeReference subjectTypes) ++ "\n\nnSubject ->\n" ++ show (ppObject subject) ++ "\n\nrel -> " ++ show (ppTypeReference tr) ++ "\n\nnRelationTypes ->\n" ++ show (ppRelationTuples relationTuples) ++ "\n\nresource -> " ++ show (ppObject resource)) $
          let (direct, others) = partition (hasSubjectType (ObjectType subjectType)) relationTuples
          in if (RelationTuple resource (Relation relName) subject Nothing) `elem` direct
               then Allowed
               else let checkOthers reasons [] = NotAllowed reasons
                        -- why would the following case happen?
                        checkOthers oldReasons ((RelationTuple res perm subj Nothing) : os) =
                          debugTrace "not sure why we are seeing this checkOthers case" $ checkOthers oldReasons os
                        checkOthers oldReasons ((RelationTuple res perm subj (Just (Relation subRelation))):os) =
                          case check' rs subj subRelation subject of
                            Allowed -> Allowed
                            (NotAllowed reasons) -> checkOthers (oldReasons ++ reasons) os
                    in checkOthers [] others
    checkExpr relationTuples (Union l r) rm =
      case checkExpr relationTuples l rm of
        Allowed -> Allowed
        NotAllowed nal ->
          case checkExpr relationTuples r rm of
            Allowed -> Allowed
            (NotAllowed nar) -> NotAllowed $ (map  (\s -> "Union - left - " <> s) nal) ++ (map (\s -> "Union - right - " <> s) nar)
    checkExpr relationTuples (Arrow (Relation arrowRel) permOrRel) rm =
      case Map.lookup arrowRel rm of
        Nothing  -> NotAllowed [ "permission  " <> perm <> " refers to a relation " <> arrowRel <> " which can not be found." ]
        (Just subjectTypes) ->
          debugTrace ("checkExpr Arrow - \nSubjectTypes -> " ++ show ({- NonEmpty.map ppTypeReference -} subjectTypes) ++ "\n" ++ show arrowRel) $
          case subjectTypes of
            (st  :| sts) ->
              let subjs = lookupSubjectsWithType relationTuples resource (Relation arrowRel) (ObjectType $ resourceType $ objectResource st)
              in debugTrace ("subjs - " ++ show subjs ++ " permOrRel - " ++ T.unpack permOrRel  ) $
                 -- fixme: this check could be done in parallel
                 -- fixme: does it makes since to pass extraTuples here? or should they have already been filtered out?
                 mconcat $ map (\subj -> check' rs subj permOrRel subject) subjs

lookupSubjects :: [RelationTuple] -> Object -> Relation -> [ Object ]
lookupSubjects tuples res rel =
  [ subj | (RelationTuple res' rel' subj mSubRelation) <- tuples, res == res', rel == rel' ]

lookupSubjectsWithType :: [RelationTuple] -> Object -> Relation -> ObjectType -> [ Object ]
lookupSubjectsWithType tuples res rel objectType =
  [ subj | (RelationTuple res' rel' subj@(Object objectType' _) mSubRelation) <- tuples, res == res', rel == rel', objectType == objectType' ]


-- * Permission Tree

data SubjectReference = SubjectReference
  { subjectObject  :: Object
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
  { expandedObject   :: Object
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


-- * Example

-- https://authzed.com/blog/check-it-out

schema1 :: Schema
schema1 =
  [schema|
    definition user {}

    definition organization {
        relation admin: user

        permission can_admin = admin
    }

    definition document {
        relation org: organization

        relation owner: user
        relation reader: user

        permission edit = owner
        permission view = reader + owner + org->can_admin

    }
|]

rels1 :: [RelationTuple]
rels1 =
  [rels|
    document:somedocument#reader@user:sean                 # Sean is a reader on somedocument
    document:somedocument#reader@user:fred                 # Fred is a reader on somedocument
    document:somedocument#owner@user:jill                  # Jill is the owner of somedocument
    organization:theorg#admin@user:hannah                  # Hannah is the admin of the organization
    document:somedocument#org@organization:theorg          # `theorg` is the organization for the document
  |]

-- some resources

somedocument :: Object
somedocument = Object (ObjectType "document") (ObjectId "somedocument")

-- some users

sean :: Object
sean = Object (ObjectType "user") (ObjectId "sean")

fred :: Object
fred = Object (ObjectType "user") (ObjectId "fred")

jill :: Object
jill = Object (ObjectType "user") (ObjectId "jill")

reader :: Relation
reader = Relation "reader"

owner :: Relation
owner = Relation "owner"

bob :: Object
bob = [object| user:bob |]

hannah :: Object
hannah = [object| user:hannah |]

-- some relation names

edit = "edit"
view = "view"

rs = mkRelationState schema1 rels1
t1 =
  do putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, view, ppObject bob)
     print $ check' rs somedocument view bob
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, view, ppObject hannah)
     print $ check' rs somedocument view hannah
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, edit, ppObject jill)
     print $ check' rs somedocument edit jill
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, edit, ppObject sean)
     print $ check' rs somedocument edit sean
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, view, ppObject sean)
     print $ check' rs somedocument view sean


schema2 =
  [schema|
    definition role {
	relation member: user | group#membership
	permission allowed = member
    }

    definition user {}

    definition group {
	relation admin: user
	relation member: user
	permission membership = admin + member
    }
 |]

rels2 =
  [rels|
     group:sharks#admin@user:chico
     role:cast#member@user:gus
     role:cast#member@group:sharks#membership
   |]

rs2 = mkRelationState schema2 rels2
