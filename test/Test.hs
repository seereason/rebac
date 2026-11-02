{-# LANGUAGE DataKinds, DeriveGeneric, GeneralizedNewtypeDeriving, OverloadedStrings, QuasiQuotes #-}

module Main (main) where

import AccessControl.Check
import AccessControl.Relation
import AccessControl.Schema
import AccessControl.Validate
import Data.Acid
import Data.Acid.Memory
import Data.Text (Text)
import Data.Time.Clock
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
    it "reports a subject relation that is a relation" $
      problems [schema| definition user {}
                        definition usergroup {
                          relation direct_member: user | usergroup#direct_member
                        } |]
        `shouldBe` [UnsupportedSubjectRelation "usergroup" "direct_member"]
    it "reports an unknown name in a permission" $
      validateSchema [schema| definition user {}
                              definition doc {
                                relation owner: user
                                permission edit = ownr
                              } |]
        `shouldBe` [SchemaError "doc" (Just "edit") (UnknownName "ownr")]
    it "reports a permission that refers to a permission" $
      problems [schema| definition user {}
                        definition doc {
                          relation owner: user
                          permission edit = owner
                          permission view = edit
                        } |]
        `shouldBe` [UnsupportedPermissionReference "edit"]
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
    it "reports an arrow target that is a relation" $
      problems [schema| definition user {}
                        definition org { relation admin: user }
                        definition doc {
                          relation org: org
                          permission view = org->admin
                        } |]
        `shouldBe` [UnsupportedArrowTarget "org" "org" "admin"]

main :: IO ()
main = hspec $ do
  describe "AccessControl" $ do
   test_Arrow
   test_Expires
   test_validateSchema
   test_subjectSets
--   test_addRelationTuple
--   test_removeRelationTuple

