{-# LANGUAGE DeriveGeneric, GeneralizedNewtypeDeriving, OverloadedStrings, TemplateHaskell #-}

module Main (main) where

import AccessControl.Acid
import AccessControl.Check
import AccessControl.Relation
import Data.Acid
import Data.Acid.Memory
import Data.Text (Text)
import Test.Hspec
import AccessControl.Acid

test_Arrow :: SpecWith ()
test_Arrow  =
 it "arrow relation" $ (
  do acid <- openMemoryState (mkRelationState schema1 rels1)
     query acid (Check somedocument view hannah)
  ) `shouldReturn` Allowed


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

main :: IO ()
main = hspec $ do
  describe "AccessControl" $ do
   test_Arrow
   test_addRelationTuple
   test_removeRelationTuple

