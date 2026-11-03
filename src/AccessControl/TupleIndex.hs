{-# language DataKinds #-}
-- | Relation tuples indexed for 'AccessControl.Check.checkIndexed'.
--
-- 'AccessControl.Check.check' needs the tuples of one resource at a time,
-- and with a plain list that means looking at every tuple on every step of
-- every check.  A 'TupleIndex' finds them by resource directly.
--
-- The representation is not exported, so other indexes (by subject, for
-- looking up the resources a subject can reach) can be added without
-- changing the callers or the serialized form, which is just the tuples.
module AccessControl.TupleIndex
  ( TupleIndex
  , emptyIndex
  , fromTuples
  , toTuples
  , tuplesFor
  , elemTuple
  , insertTuple
  , deleteTuple
  , indexedResources
  ) where

import AccessControl.Relation (Object, ObjectWildcard(..), RelationTuple(..))
import Control.Monad (forM_, replicateM)
import Data.Map (Map)
import qualified Data.Map as Map
import Data.SafeCopy (SafeCopy(..), contain, getSafeGet, getSafePut)
import Data.Serialize (get, put)

newtype TupleIndex = TupleIndex
  { byResource :: Map (Object 'NoWildcard) [RelationTuple] -- ^ each resource's tuples, in the order they were given
  }
  deriving (Eq, Ord, Read, Show)

-- | Serialized exactly as the @[RelationTuple]@ of its 'toTuples' would be,
-- with the same (default) version and kind and the same encoding as
-- safecopy's list instance, so a @[RelationTuple]@ field can become a
-- 'TupleIndex' without changing the stored format.  The index is rebuilt
-- when it is read.
instance SafeCopy TupleIndex where
  putCopy idx = contain $ do
    let rts = toTuples idx
    put (length rts)
    getSafePut >>= forM_ rts
  getCopy = contain $ do
    n <- get
    g <- getSafeGet
    fromTuples <$> replicateM n g
  errorTypeName _ = "TupleIndex"

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

-- | is this tuple in the index?  Looks only at its resource's tuples.
elemTuple :: RelationTuple -> TupleIndex -> Bool
elemTuple rt = elem rt . tuplesFor (resource rt)

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
