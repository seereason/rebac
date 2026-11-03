{-# LANGUAGE DataKinds, DeriveGeneric, GeneralizedNewtypeDeriving, OverloadedStrings, QuasiQuotes, TemplateHaskell #-}

module Main (main) where

import AccessControl.Check
import AccessControl.Relation
import AccessControl.Schema
import AccessControl.SchemaFragment
import AccessControl.TupleIndex
import AccessControl.Validate
import Data.Acid
import Data.Acid.Memory
import Data.Either (isRight)
import Data.List (nub, sort)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Fixtures (baseFragment)
import Data.Time.Clock
import Data.SafeCopy (SafeCopy(..), base, safeGet, safePut)
import Data.Serialize (runGet, runPut)
import GHC.Generics (Generic)
import Test.Hspec

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
        relation reader: user | user:* | user with expiration

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
    document:publicdoc#reader@user:*                       # a publicly readable document
    document:somedocument#reader@user:tom[expiration:2040-12-31T23:59:59Z] # Tom is a reader on somedocument, but only until 2040
  |]

-- some resources

somedocument :: Object NoWildcard
somedocument = Object (ObjectType "document") (ObjectId "somedocument")

publicdoc :: Object NoWildcard
publicdoc = Object (ObjectType "document") (ObjectId "publicdoc")

-- some users

sean :: Object NoWildcard
sean = Object (ObjectType "user") (ObjectId "sean")

fred :: Object NoWildcard
fred = Object (ObjectType "user") (ObjectId "fred")

jill :: Object NoWildcard
jill = Object (ObjectType "user") (ObjectId "jill")

reader :: Relation
reader = Relation "reader"

owner :: Relation
owner = Relation "owner"

bob :: Object NoWildcard
bob = [object| user:bob |]

hannah :: Object NoWildcard
hannah = [object| user:hannah |]

tom :: Object NoWildcard
tom = [object| user:tom |]

-- some relation names

edit = Permission "edit"
view = Permission "view"


defMap1 = mkDefMap (definitions schema1)

t1 =
  do putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, view, ppObject bob)
     print $ check defMap1 rels1 somedocument view bob Nothing
     putStrLn $ "expected: NotAllowed - not an owner, reader, or admin"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, view, ppObject hannah)
     print $ check defMap1 rels1 somedocument view hannah Nothing
     putStrLn $ "expected: Allowed - hannah is an admin"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, edit, ppObject jill)
     print $ check defMap1 rels1 somedocument edit jill Nothing
     putStrLn $ "expected: Allowed - jill is the owner"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, edit, ppObject sean)
     print $ check defMap1 rels1 somedocument edit sean Nothing
     putStrLn $ "expected: NotAllowed - sean is not the owner or an admin"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, view, ppObject sean)
     print $ check defMap1 rels1 somedocument view sean Nothing
     putStrLn $ "expected: Allowed - sean is a reader"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject publicdoc, view, ppObject sean)
     print $ check defMap1 rels1 publicdoc view sean Nothing
     putStrLn $ "expected: Allowed - the publicdoc should be readable by everyone"


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

test_Arrow :: SpecWith ()
test_Arrow  =
 it "arrow relation" $ pure (
  check (mkDefMap $ definitions schema1) rels1 somedocument view hannah Nothing   --- query acid (Check somedocument view hannah)
  ) `shouldReturn` Allowed


test_Expires :: SpecWith ()
test_Expires =
  it "expiring relations" $
    do pure (check (mkDefMap $ definitions schema1) rels1 somedocument view tom (Just (realToFrac 1763418777.734767739))) `shouldReturn` Allowed


{-
test_addRelationTuple :: SpecWith ()
test_addRelationTuple  =
 it "addRelationTuple" $ (
  do acid <- openMemoryState (mkRelationState schema1 rels1)
     update acid (AddRelationTuple (RelationTuple somedocument reader bob))
     query acid (Check somedocument view bob)
  ) `shouldReturn` Allowed

test_removeRelationTuple :: SpecWith ()
test_removeRelationTuple  =
 it "removeRelationTuple" $ (
  do acid <- openMemoryState (mkRelationState schema1 rels1)
     update acid (RemoveRelationTuple (RelationTuple somedocument reader sean))
     r <- query acid (Check somedocument view sean)
     pure $ case r of
       Allowed -> Allowed
       NotAllowed _ -> NotAllowed []
  ) `shouldReturn` (NotAllowed [])
-}

-- * Subject sets

groupSchema :: Schema
groupSchema =
  [schema|
    definition user {}

    definition usergroup {
      relation direct_member: user | usergroup#member
      permission member = direct_member
    }

    definition page {
      relation admin: user
      relation viewer: user | usergroup#member | user:*
      permission view = viewer + admin
      permission edit = admin
    }
  |]

groupRels :: [RelationTuple]
groupRels =
  [rels|
    page:1#viewer@usergroup:x#member              # members of x can view page 1
    page:1#admin@user:bob                         # bob administers page 1
    usergroup:x#direct_member@user:alice          # alice is a member of x
    usergroup:x#direct_member@usergroup:y#member  # members of y are members of x
    usergroup:y#direct_member@user:carol          # carol is a member of y
  |]

-- | is the subject allowed the permission on the resource, under groupSchema and groupRels
groupCheck :: Object NoWildcard -> Permission -> Object NoWildcard -> Bool
groupCheck res perm subj = isAllowed (check (mkDefMap (definitions groupSchema)) groupRels res perm subj Nothing)

test_subjectSets :: SpecWith ()
test_subjectSets =
  describe "subject sets" $ do
    it "grants view to a member of a group that can view" $
      groupCheck [object| page:1 |] view [object| user:alice |] `shouldBe` True
    it "grants view through a nested group" $
      groupCheck [object| page:1 |] view [object| user:carol |] `shouldBe` True
    it "does not grant edit through the viewer relation's subject set" $
      groupCheck [object| page:1 |] edit [object| user:alice |] `shouldBe` False
    it "does not grant edit through a nested group either" $
      groupCheck [object| page:1 |] edit [object| user:carol |] `shouldBe` False
    it "grants edit to an admin" $
      groupCheck [object| page:1 |] edit [object| user:bob |] `shouldBe` True
    it "does not grant view to a non-member" $
      groupCheck [object| page:1 |] view [object| user:dave |] `shouldBe` False
    it "does not treat the group itself as one of its members" $
      groupCheck [object| page:1 |] view [object| usergroup:x |] `shouldBe` False

-- * Cycles

-- | groups a and b are members of each other, and c is a member of itself
cycleRels :: [RelationTuple]
cycleRels =
  [rels|
    page:2#viewer@usergroup:a#member
    page:3#viewer@usergroup:c#member
    usergroup:a#direct_member@usergroup:b#member
    usergroup:b#direct_member@usergroup:a#member
    usergroup:b#direct_member@user:erin
    usergroup:c#direct_member@usergroup:c#member
  |]

cycleCheck :: Object NoWildcard -> Permission -> Object NoWildcard -> Bool
cycleCheck res perm subj = isAllowed (check (mkDefMap (definitions groupSchema)) cycleRels res perm subj Nothing)

-- | folders a and b are each other's parent
folderSchema :: Schema
folderSchema =
  [schema|
    definition user {}

    definition folder {
      relation parent: folder
      relation owner: user
      permission view = owner + parent->view
    }
  |]

folderRels :: [RelationTuple]
folderRels =
  [rels|
    folder:a#parent@folder:b
    folder:b#parent@folder:a
    folder:b#owner@user:erin
  |]

folderCheck :: Object NoWildcard -> Permission -> Object NoWildcard -> Bool
folderCheck res perm subj = isAllowed (check (mkDefMap (definitions folderSchema)) folderRels res perm subj Nothing)

test_cycles :: SpecWith ()
test_cycles =
  describe "cycles" $ do
    it "finds a member through groups that are members of each other" $
      cycleCheck [object| page:2 |] view [object| user:erin |] `shouldBe` True
    it "terminates for a non-member of groups that are members of each other" $
      cycleCheck [object| page:2 |] view [object| user:dave |] `shouldBe` False
    it "terminates for a group that is a member of itself" $
      cycleCheck [object| page:3 |] view [object| user:erin |] `shouldBe` False
    it "finds an owner through folders that are each other's parent" $
      folderCheck [object| folder:a |] view [object| user:erin |] `shouldBe` True
    it "terminates for a non-owner of folders that are each other's parent" $
      folderCheck [object| folder:a |] view [object| user:dave |] `shouldBe` False

-- * Names that are relations or permissions

-- | uses a relation or permission wherever either may appear
nameSchema :: Schema
nameSchema =
  [schema|
    definition user {}

    definition usergroup {
      relation direct_member: user
    }

    definition org {
      relation admin: user
    }

    definition doc {
      relation owner: user
      relation org: org
      relation reader: usergroup#direct_member
      permission edit = owner
      permission view = edit + reader
      permission manage = org->admin
      permission a = b
      permission b = a
    }
  |]

nameRels :: [RelationTuple]
nameRels =
  [rels|
    doc:1#owner@user:jill
    doc:1#org@org:acme
    doc:1#reader@usergroup:x#direct_member
    org:acme#admin@user:hannah
    usergroup:x#direct_member@user:alice
  |]

nameCheck :: Object NoWildcard -> Permission -> Object NoWildcard -> Bool
nameCheck res perm subj = isAllowed (check (mkDefMap (definitions nameSchema)) nameRels res perm subj Nothing)

test_names :: SpecWith ()
test_names =
  describe "relations and permissions by name" $ do
    it "evaluates a permission that refers to a permission" $
      nameCheck [object| doc:1 |] view [object| user:jill |] `shouldBe` True
    it "follows a subject set whose subject relation is a relation" $
      nameCheck [object| doc:1 |] view [object| user:alice |] `shouldBe` True
    it "follows an arrow whose target is a relation" $
      nameCheck [object| doc:1 |] (Permission "manage") [object| user:hannah |] `shouldBe` True
    it "does not follow the arrow for someone else" $
      nameCheck [object| doc:1 |] (Permission "manage") [object| user:jill |] `shouldBe` False
    it "checks a relation directly" $
      nameCheck [object| doc:1 |] (Permission "owner") [object| user:jill |] `shouldBe` True
    it "does not grant a relation to someone without it" $
      nameCheck [object| doc:1 |] (Permission "owner") [object| user:alice |] `shouldBe` False
    it "terminates for permissions defined in terms of each other" $
      nameCheck [object| doc:1 |] (Permission "a") [object| user:jill |] `shouldBe` False

-- | do all the tuples validate under groupSchema
groupValid :: [RelationTuple] -> Bool
groupValid = all (isValid . validate (mkDefMap (definitions groupSchema)))

test_validateSubjectRelation :: SpecWith ()
test_validateSubjectRelation =
  describe "validate with subject relations" $ do
    it "accepts a subject set the relation allows" $
      groupValid [rels|page:1#viewer@usergroup:x#member|] `shouldBe` True
    it "accepts a plain subject the relation allows" $
      groupValid [rels|page:1#viewer@user:7|] `shouldBe` True
    it "accepts a wildcard the relation allows" $
      groupValid [rels|page:1#viewer@user:*|] `shouldBe` True
    it "rejects a plain subject where only a subject set is allowed" $
      groupValid [rels|page:1#viewer@usergroup:x|] `shouldBe` False
    it "rejects a subject set with the wrong subject relation" $
      groupValid [rels|page:1#viewer@usergroup:x#direct_member|] `shouldBe` False
    it "rejects a subject relation where only a plain subject is allowed" $
      groupValid [rels|page:1#viewer@user:7#member|] `shouldBe` False
    it "rejects a wildcard subject set" $
      groupValid [rels|page:1#viewer@usergroup:*#member|] `shouldBe` False
    it "rejects a subject type the relation does not allow" $
      groupValid [rels|page:1#admin@usergroup:x#member|] `shouldBe` False
    it "rejects a wildcard where wildcards are not allowed" $
      groupValid [rels|page:1#admin@user:*|] `shouldBe` False

-- | the problems 'validateSchema' finds, without the definition and member they were found in
problems :: Schema -> [SchemaProblem]
problems = map seProblem . validateSchema

test_validateSchema :: SpecWith ()
test_validateSchema =
  describe "validateSchema" $ do
    it "accepts schema1" $ validateSchema schema1 `shouldBe` []
    it "accepts schema2" $ validateSchema schema2 `shouldBe` []
    it "reports a duplicate definition" $
      validateSchema [schema| definition user {}
                              definition user {} |]
        `shouldBe` [SchemaError "user" Nothing DuplicateDefinition]
    it "reports a duplicate member" $
      validateSchema [schema| definition user {}
                              definition doc {
                                relation owner: user
                                permission owner = owner
                              } |]
        `shouldBe` [SchemaError "doc" (Just "owner") DuplicateMember]
    it "reports an unknown type" $
      validateSchema [schema| definition doc { relation owner: usr } |]
        `shouldBe` [SchemaError "doc" (Just "owner") (UnknownType "usr")]
    it "reports an unknown subject relation" $
      validateSchema [schema| definition user {}
                              definition usergroup {
                                relation direct_member: user | usergroup#member
                                permission membership = direct_member
                              } |]
        `shouldBe` [SchemaError "usergroup" (Just "direct_member") (UnknownSubjectRelation "usergroup" "member")]
    it "accepts a subject relation that is a relation" $
      problems [schema| definition user {}
                        definition usergroup {
                          relation direct_member: user | usergroup#direct_member
                        } |]
        `shouldBe` []
    it "reports an unknown name in a permission" $
      validateSchema [schema| definition user {}
                              definition doc {
                                relation owner: user
                                permission edit = ownr
                              } |]
        `shouldBe` [SchemaError "doc" (Just "edit") (UnknownName "ownr")]
    it "accepts a permission that refers to a permission" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission edit = owner
                          permission view = edit
                        } |]
        `shouldBe` []
    it "reports & and -" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          relation banned: user
                          permission a = owner & banned
                          permission b = owner - banned
                        } |]
        `shouldBe` [UnsupportedOperator "&", UnsupportedOperator "-"]
    it "reports an arrow from a permission" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission edit = owner
                          permission view = edit->x
                        } |]
        `shouldBe` [ArrowFromPermission "edit"]
    it "reports an arrow from a wildcard relation" $
      problems [schema| definition user { relation self: user
                                          permission x = self }
                        definition doc {
                          relation reader: user | user:*
                          permission view = reader->x
                        } |]
        `shouldBe` [ArrowFromWildcard "reader"]
    it "reports an arrow over a relation with more than one type" $
      problems [schema| definition user { relation self: user
                                          permission x = self }
                        definition org { relation self: user
                                         permission x = self }
                        definition doc {
                          relation parent: user | org
                          permission view = parent->x
                        } |]
        `shouldBe` [UnsupportedArrowRelation "parent"]
    it "reports an arrow target that does not exist" $
      problems [schema| definition user {}
                        definition org { relation admin: user
                                         permission can_admin = admin }
                        definition doc {
                          relation org: org
                          permission view = org->can_admn
                        } |]
        `shouldBe` [ArrowTargetMissing "org" "org" "can_admn"]
    it "accepts an arrow target that is a relation" $
      problems [schema| definition user {}
                        definition org { relation admin: user }
                        definition doc {
                          relation org: org
                          permission view = org->admin
                        } |]
        `shouldBe` []
    -- These follow what SpiceDB v1.52.0 accepts and rejects: a cycle of
    -- permissions is an error only if nothing in it leads out of it.
    it "reports permissions defined only in terms of each other" $
      validateSchema [schema| definition user {}
                              definition doc {
                                relation owner: user
                                permission perm_a = perm_b
                                permission perm_b = perm_a
                              } |]
        `shouldBe` [SchemaError "doc" Nothing (PermissionCycle ["perm_a", "perm_b"])]
    it "reports a permission defined only in terms of itself" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission perm_a = perm_a
                        } |]
        `shouldBe` [PermissionCycle ["perm_a"]]
    it "reports a cycle alongside other permissions" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission perm_a = perm_b
                          permission perm_b = perm_a
                          permission view = owner
                        } |]
        `shouldBe` [PermissionCycle ["perm_a", "perm_b"]]
    it "reports separate cycles in one error" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission perm_a = perm_b
                          permission perm_b = perm_a
                          permission perm_c = perm_c
                        } |]
        `shouldBe` [PermissionCycle ["perm_a", "perm_b", "perm_c"]]
    it "reports a permission that only leads into a cycle" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission view = perm_a
                          permission perm_a = perm_b
                          permission perm_b = perm_a
                        } |]
        `shouldBe` [PermissionCycle ["perm_a", "perm_b", "view"]]
    it "does not report a permission that uses a cycle and a relation" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission perm_a = perm_b
                          permission perm_b = perm_a
                          permission view = perm_a + owner
                        } |]
        `shouldBe` [PermissionCycle ["perm_a", "perm_b"]]
    it "accepts a cycle that also names a relation" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission perm_a = perm_b + owner
                          permission perm_b = perm_a
                        } |]
        `shouldBe` []
    it "accepts a cycle where the relation is on the other permission" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission perm_a = perm_b
                          permission perm_b = perm_a + owner
                        } |]
        `shouldBe` []
    it "accepts a cycle that leaves through an arrow" $
      problems [schema| definition user {}
                        definition folder {
                          relation parent: folder
                          permission perm_a = perm_b
                          permission perm_b = perm_a + parent->perm_a
                        } |]
        `shouldBe` []

-- * Tuple index

-- | every fixture's tuples together
allFixtureRels :: [RelationTuple]
allFixtureRels = rels1 ++ rels2 ++ groupRels ++ cycleRels ++ folderRels ++ nameRels

-- | records like 'RebacState' with tuples in one field, before and after the
-- field became a 'TupleIndex', with the generic SafeCopy instances it uses
data WithList = WithList Int [RelationTuple] deriving (Eq, Show, Generic)
instance SafeCopy WithList where version = 2 ; kind = base
data WithIndex = WithIndex Int TupleIndex deriving (Eq, Show, Generic)
instance SafeCopy WithIndex where version = 2 ; kind = base

test_tupleIndex :: SpecWith ()
test_tupleIndex =
  describe "tuple index" $ do
    it "finds each resource's tuples, in their original order" $
      and [ tuplesFor r (fromTuples allFixtureRels) == filter ((== r) . resource) allFixtureRels
          | r <- nub (map resource allFixtureRels) ]
        `shouldBe` True
    it "has nothing for a resource with no tuples" $
      tuplesFor [object| page:999 |] (fromTuples allFixtureRels) `shouldBe` []
    it "keeps every tuple" $
      sort (toTuples (fromTuples allFixtureRels)) `shouldBe` sort allFixtureRels
    it "adds a tuple after the others for its resource" $
      let [t] = [rels| page:1#admin@user:zoe |]
      in tuplesFor [object| page:1 |] (insertTuple t (fromTuples groupRels))
           `shouldBe` (filter ((== [object| page:1 |]) . resource) groupRels ++ [t])
    it "removes a tuple, and a resource left with none" $
      let [t] = [rels| page:1#admin@user:bob |]
          idx = deleteTuple t (fromTuples [t])
      in (toTuples idx, indexedResources idx) `shouldBe` ([], [])
    it "finds a tuple that is there, and not one that is not" $
      let [t, u] = [rels| page:1#admin@user:bob
                          page:1#admin@user:zoe |]
      in (elemTuple t (fromTuples groupRels), elemTuple u (fromTuples groupRels)) `shouldBe` (True, False)
    it "serializes exactly as the list of its tuples" $
      let idx = fromTuples allFixtureRels
      in runPut (safePut idx) `shouldBe` runPut (safePut (toTuples idx))
    it "serializes as a record field exactly as a list field" $
      let idx = fromTuples allFixtureRels
      in runPut (safePut (WithIndex 7 idx)) `shouldBe` runPut (safePut (WithList 7 (toTuples idx)))
    it "reads a serialized list of tuples back as an index" $
      runGet safeGet (runPut (safePut (WithList 7 allFixtureRels)))
        `shouldBe` Right (WithIndex 7 (fromTuples allFixtureRels))

-- * Schema fragments

-- | read and checked when this module is compiled, against 'baseFragment'
pageFragment :: SchemaFragment
pageFragment = $(schemaFragmentFile [baseFragment] "test/fixtures/page.schema")

-- | the distinct problems 'checkFragment' found, if it found any
fragmentProblems :: Either FragmentError SchemaFragment -> [SchemaProblem]
fragmentProblems (Left (FragmentInconsistent es)) = sort (nub (map seProblem es))
fragmentProblems _ = []

isFragmentParseError :: Either FragmentError SchemaFragment -> Bool
isFragmentParseError (Left (FragmentParseError _)) = True
isFragmentParseError _ = False

test_fragments :: SpecWith ()
test_fragments =
  describe "schema fragments" $ do
    it "keeps a spliced file's text, comments included" $ do
      file <- T.readFile "test/fixtures/page.schema"
      fragmentText pageFragment `shouldBe` file
    it "parses a spliced file" $
      map defName (definitions (fragmentSchema pageFragment)) `shouldBe` ["page"]
    it "records what a fragment depends on" $
      fragmentDepends pageFragment `shouldBe` [baseFragment]
    it "accepts a fragment that uses its dependencies' types" $
      isRight (checkFragment [baseFragment] (fragmentText pageFragment)) `shouldBe` True
    it "reports types a fragment uses without depending on them" $
      fragmentProblems (checkFragment [] (fragmentText pageFragment)) `shouldBe` [UnknownType "user", UnknownType "usergroup"]
    it "accepts types that come from a dependency's dependency" $
      isRight (checkFragment [pageFragment] "definition doc { relation reader: usergroup#member }") `shouldBe` True
    it "reports a definition that a dependency already has" $
      checkFragment [baseFragment] "definition user {}"
        `shouldBe` Left (FragmentInconsistent [SchemaError "user" Nothing DuplicateDefinition])
    it "reports a parse error" $
      isFragmentParseError (checkFragment [] "definition doc {") `shouldBe` True
    it "merges fragments into one schema, keeping their comments" $
      case mergeFragments [baseFragment, pageFragment] of
        Left errs -> expectationFailure (show errs)
        Right (txt, sch) -> do
          map defName (definitions sch) `shouldBe` ["user", "usergroup", "page"]
          ("/* the page plugin's part of the schema */" `T.isInfixOf` txt) `shouldBe` True
          parseSchema txt `shouldBe` Right sch
    it "reports a dependency missing from the merge" $
      either (sort . nub . map seProblem) (const []) (mergeFragments [pageFragment])
        `shouldBe` [UnknownType "user", UnknownType "usergroup"]
    it "reports a fragment merged twice" $
      either (map seProblem) (const []) (mergeFragments [baseFragment, baseFragment])
        `shouldBe` [DuplicateDefinition, DuplicateDefinition]

main :: IO ()
main = hspec $ do
  describe "AccessControl" $ do
   test_Arrow
   test_Expires
   test_validateSchema
   test_subjectSets
   test_validateSubjectRelation
   test_cycles
   test_names
   test_fragments
   test_tupleIndex
--   test_addRelationTuple
--   test_removeRelationTuple

