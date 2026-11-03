{-# language DataKinds #-}
-- | Relation tuples indexed for 'AccessControl.Check.checkIndexed'.
--
-- 'AccessControl.Check.check' needs the tuples of one resource at a time,
-- and with a plain list that means looking at every tuple on every step of
-- every check.  A 'TupleIndex' finds them by resource directly.
--
-- The representation is not exported, so other indexes (by subject, for
-- looking up the resources a subject can reach) can be added without
-- changing the callers.
module AccessControl.TupleIndex
  ( TupleIndex
  , emptyIndex
  , fromTuples
  , toTuples
  , tuplesFor
  , insertTuple
  , deleteTuple
  , indexedResources
  ) where

import AccessControl.Relation (Object, ObjectWildcard(..), RelationTuple(..))
import Data.Map (Map)
import qualified Data.Map as Map

newtype TupleIndex = TupleIndex
  { byResource :: Map (Object 'NoWildcard) [RelationTuple] -- ^ each resource's tuples, in the order they were given
  }
  deriving (Eq, Show)

emptyIndex :: TupleIndex
emptyIndex = TupleIndex Map.empty

-- | index a list of tuples, keeping their order within each resource
fromTuples :: [RelationTuple] -> TupleIndex
fromTuples rts = TupleIndex (Map.fromListWith (flip (++)) [ (resource rt, [rt]) | rt <- rts ])

-- | every indexed tuple, grouped by resource
toTuples :: TupleIndex -> [RelationTuple]
toTuples = concat . Map.elems . byResource

-- | the tuples whose resource is this one
tuplesFor :: Object 'NoWildcard -> TupleIndex -> [RelationTuple]
tuplesFor res = Map.findWithDefault [] res . byResource

-- | add a tuple, after any others for its resource
insertTuple :: RelationTuple -> TupleIndex -> TupleIndex
insertTuple rt = TupleIndex . Map.insertWith (flip (++)) (resource rt) [rt] . byResource

-- | remove every copy of a tuple
deleteTuple :: RelationTuple -> TupleIndex -> TupleIndex
deleteTuple rt = TupleIndex . Map.update keep (resource rt) . byResource
  where
    keep rts = case filter (/= rt) rts of
                 []    -> Nothing
                 rts'  -> Just rts'

-- | the resources that have at least one tuple
indexedResources :: TupleIndex -> [Object 'NoWildcard]
indexedResources = Map.keys . byResource
