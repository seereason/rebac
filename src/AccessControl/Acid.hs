{- DEPRECATED, NOT IN USE -}
{-# language TemplateHaskell   #-}
{-# language TypeFamilies      #-}
{-# language OverloadedStrings #-}
module AccessControl.Acid where

import AccessControl.Check
import AccessControl.Relation
import AccessControl.Schema

import Data.Acid
import Data.SafeCopy
import Data.Map (Map)
import Data.Text (Text)
import Control.Monad.Reader
import Control.Monad.State

putSchema :: Schema -> Update RelationState ()
putSchema s@(Schema defs) =
  do rs <- get
     put (rs { rsDefMap = mkDefMap defs
             , rsSchema = s
             })

getSchema :: Query RelationState Schema
getSchema =
  do rs <- ask
     pure $ rsSchema rs

check :: Object     -- ^ resource
      -> Permission -- ^ permission
      -> Object     -- ^ subject
      -> Query RelationState Access
check resource (Permission perm) subject =
  do rs <- ask
     pure $ check' rs resource perm subject

addRelationTuple :: RelationTuple -> Update RelationState ()
addRelationTuple rt =
  do rs <- get
     if rt `elem` (rsTuples rs)
       then pure ()
       else put $ rs { rsTuples = rt : (rsTuples rs) }

removeRelationTuple :: RelationTuple -> Update RelationState ()
removeRelationTuple rt =
  do rs <- get
     put $ rs { rsTuples = filter ((/=) rt) (rsTuples rs) }

getRelationTuples :: Query RelationState [ RelationTuple ]
getRelationTuples =
  do rs <- ask
     pure $ rsTuples rs

makeAcidic ''RelationState
  [ 'getSchema
  , 'putSchema
  , 'check
  , 'addRelationTuple
  , 'removeRelationTuple
  , 'getRelationTuples
  ]
