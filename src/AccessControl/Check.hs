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
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import           Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import Data.Typeable (Typeable)
import Data.Void (Void)
import GHC.Generics
import Text.PrettyPrint.HughesPJ (Doc, (<+>), ($$), ($+$))
import qualified Text.PrettyPrint.HughesPJ as PP


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
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

mkRelationState :: Schema -> [RelationTuple] -> RelationState
mkRelationState (Schema defs) tuples =
  RelationState { rsTuples      = tuples
                , rsDefMap      = mkDefMap
                }
  where
    mkDefMap = Map.fromList $ map mkDefMapItem defs
    mkDefMapItem (Definition nm decls) =
      let (rels, perms) = partitionEithers decls
          relMap  = Map.fromList $ map (\(ObjectRelation nm ot) -> (nm, ot)) rels
          permMap = Map.fromList $ map (\(ObjectPermission nm ex) -> (nm, ex)) perms
      in (nm, RelPerm relMap permMap)

{-
  let (rels, perms) = partitionEithers defs

-}
{-
defs :: Schema -> Map Text Definition
schemaTopMap (Schema defs) =
  Map.fromList $ map (\d -> (defName d, defDecls
  -}
data Access
  = Allowed
  | NotAllowed Text
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

{-
As an alternative implementation -- could we have a lazy function which expands the permission tree, and then a second function which just searches that tree.

The expansion function seems useful for diagnostic purposes.
-}
check :: RelationState
      -> Object -- ^ resource
      -> Text   -- ^ permission
      -> Object -- ^ subject
      -> Access
check (RelationState rsTuples rsDefMap) resource@(Object (ObjectType resourceType) (ObjectId resourceId)) perm subject@(Object (ObjectType subjectType) (ObjectId subjectId)) =
  -- find the subset of RelationTuples which are relevant to the requested 'Resource'
  case filter (\(RelationTuple resource' _ _) -> resource == resource') rsTuples of
    [] -> NotAllowed "no tuples for resource located"
    relationTuples ->
      -- find the object definition that is relevant to the 'resourceType'
      case Map.lookup resourceType rsDefMap of
           Nothing -> NotAllowed $ "object not found in definitions - " <> resourceType
           (Just (RelPerm rm pm)) ->
             -- find the requested permission
             case Map.lookup perm pm of
               Nothing -> NotAllowed $ "permission " <> perm <> " not defined for resource " <> resourceType
               (Just expr) -> checkExpr  relationTuples expr rm
  where
    checkExpr :: [ RelationTuple ] -> PermissionExpression -> Map Text (NonEmpty TypeReference) -> Access
    checkExpr relationTuples (Ref tr@(TypeReference (Resource relName Nothing) Nothing)) rm =
      case Map.lookup relName rm of
        Nothing  -> NotAllowed $ "permission  " <> perm <> " refers to a relation " <> relName <> " which can not be found."
        (Just subjectTypes) ->
          if (TypeReference (Resource "user" Nothing) Nothing) `elem` subjectTypes
          then if (RelationTuple resource (Relation relName) subject) `elem` relationTuples
               then Allowed
               else NotAllowed (T.pack $ show subjectTypes)
          else NotAllowed ((T.pack $ show $ ppObject subject) <> " does not match " <> (T.pack $ show subjectTypes))


--             error ("\n" ++ (show $ ppRelationTuples r) ++ "\n\n" ++ (show $ ppRelPerm relPerms))

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

    permission view = reader + owner
    permission edit = owner
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


somedocument :: Object
somedocument = Object (ObjectType "document") (ObjectId "somedocument")

sean :: Object
sean = Object (ObjectType "user") (ObjectId "sean")

fred :: Object
fred = Object (ObjectType "user") (ObjectId "fred")

jill :: Object
jill = Object (ObjectType "user") (ObjectId "jill")

rs = mkRelationState schema1 rels1
t1 = check rs  somedocument "edit" jill

