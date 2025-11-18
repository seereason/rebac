{-# LANGUAGE DataKinds, DeriveGeneric, GeneralizedNewtypeDeriving, OverloadedStrings, QuasiQuotes #-}

module Main (main) where

import AccessControl.Check
import AccessControl.Relation
import AccessControl.Schema
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

main :: IO ()
main = hspec $ do
  describe "AccessControl" $ do
   test_Arrow
   test_Expires
--   test_addRelationTuple
--   test_removeRelationTuple

