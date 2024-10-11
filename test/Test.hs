{-# LANGUAGE DataKinds, DeriveGeneric, GeneralizedNewtypeDeriving, OverloadedStrings, QuasiQuotes #-}

module Main (main) where

import AccessControl.Check
import AccessControl.Relation
import AccessControl.Schema
import Data.Acid
import Data.Acid.Memory
import Data.Text (Text)
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
        relation reader: user | user:*

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
  |]

-- some resources

somedocument :: Object ResourceK
somedocument = Object (ObjectType "document") (ResourceId "somedocument")

publicdoc :: Object ResourceK
publicdoc = Object (ObjectType "document") (ResourceId "publicdoc")

-- some users

sean :: Object SubjectK
sean = Object (ObjectType "user") (SubjectId "sean")

fred :: Object SubjectK
fred = Object (ObjectType "user") (SubjectId "fred")

jill :: Object SubjectK
jill = Object (ObjectType "user") (SubjectId "jill")

reader :: Relation
reader = Relation "reader"

owner :: Relation
owner = Relation "owner"

bob :: Object SubjectK
bob = [subj| user:bob |]

hannah :: Object SubjectK
hannah = [subj| user:hannah |]

-- some relation names

edit = Permission "edit"
view = Permission "view"


defMap1 = mkDefMap (definitions schema1)

t1 =
  do putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, view, ppObject bob)
     print $ check defMap1 rels1 somedocument view bob
     putStrLn $ "expected: NotAllowed - not an owner, reader, or admin"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, view, ppObject hannah)
     print $ check defMap1 rels1 somedocument view hannah
     putStrLn $ "expected: Allowed - hannah is an admin"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, edit, ppObject jill)
     print $ check defMap1 rels1 somedocument edit jill
     putStrLn $ "expected: Allowed - jill is the owner"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, edit, ppObject sean)
     print $ check defMap1 rels1 somedocument edit sean
     putStrLn $ "expected: NotAllowed - sean is not the owner or an admin"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject somedocument, view, ppObject sean)
     print $ check defMap1 rels1 somedocument view sean
     putStrLn $ "expected: Allowed - sean is a reader"
     putStrLn "-----------------------------------------------------"
     print $ (ppObject publicdoc, view, ppObject sean)
     print $ check defMap1 rels1 publicdoc view sean
     putStrLn $ "expected: Allowed - the document should be readable by everyone"


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
  check (mkDefMap $ definitions schema1) rels1 somedocument view hannah   --- query acid (Check somedocument view hannah)
  ) `shouldReturn` Allowed


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

main :: IO ()
main = hspec $ do
  describe "AccessControl" $ do
   test_Arrow
--   test_addRelationTuple
--   test_removeRelationTuple

