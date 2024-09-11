{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language MultiParamTypeClasses #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes, TemplateHaskell, DeriveLift #-}
module AccessControl.Relation where

import AccessControl.Schema (Permission(..), Relation(..), ToPermission(..), ToRelation(..), pName, pRelation, ppRelation, pObjectType, ppObjectType, ppText)
import Data.Data (Data)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.SafeCopy (SafeCopy)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Typeable (Typeable)
import Data.Void (Void)
import GHC.Generics
import Language.Haskell.TH
import Language.Haskell.TH.Quote
import Language.Haskell.TH.Syntax
import Language.Haskell.TH.Lib (tupleT)

import Text.Megaparsec
import Text.Megaparsec.Char
import Text.PrettyPrint.HughesPJ (Doc, (<+>), ($$), ($+$))
import qualified Text.PrettyPrint.HughesPJ as PP
import qualified Text.Megaparsec.Char.Lexer as L -- (1)

import AccessControl.Schema (ObjectType(..),sc, scnl) -- for Lift Text instance

-- FIXME: how does string escaping work?


type Parser = Parsec Void Text

{-
newtype ObjectType = ObjectType { unObjectType :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)
-}

-- * ObjectId

-- An `ObjectId` identifies an object within an `ObjectType` namespace
newtype ObjectId = ObjectId { unObjectId :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectId

ppObjectId :: ObjectId -> Doc
ppObjectId (ObjectId i) = ppText i

pObjectId :: Parser ObjectId
pObjectId = ObjectId <$> pName

-- * Object

-- | An 'Object' has an 'ObjectType' and 'ObjectId'.
--
-- An 'Object' identifies a resource or subject.
--
-- The 'ObjectId' is unique for an particular 'ObjectType' but not across all 'ObjectTypes'.
data Object = Object
  { objectType :: ObjectType
  , objectId   :: ObjectId
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy Object

class ToObject a where
  toObject :: a -> Object

instance ToObject Object where
  toObject = id

ppObject :: Object -> Doc
ppObject (Object ot oi) =
  ppObjectType ot <> PP.char ':' <> ppObjectId oi

pObject :: Parser Object
pObject =
  do ot <- pObjectType
     char ':'
     oi <- pObjectId
     pure $ Object ot oi

-- * RelationTuple

-- | Define a relationship between a 'resource' and 'subject'
data RelationTuple = RelationTuple
  { resource :: Object
  , relation :: Relation
  , subject  :: Object
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy RelationTuple

class (ToObject resource, ToPermission permission, ToObject subject) => KnownPermission resource permission subject
instance KnownPermission Object Permission Object
{-
toRelationTuple :: (KnownPermission resource relation subject, ToObject resource, ToRelation relation, ToObject subject) => resource -> relation -> subject -> RelationTuple
toRelationTuple resource relation subject = RelationTuple (toObject resource) (toRelation relation) (toObject subject)
-}
ppRelationTuple :: RelationTuple -> Doc
ppRelationTuple (RelationTuple res rel subj) =
  ppObject res <> PP.char '#' <> ppRelation rel <> PP.char '@' <> ppObject subj

ppRelationTuples :: [RelationTuple] -> Doc
ppRelationTuples rt =
  PP.vcat $ map ppRelationTuple rt

pRelationTuple :: Parser RelationTuple
pRelationTuple =
  do res <- pObject
     char '#'
     rel <- pRelation
     char '@'
     subj <- pObject
     pure $ RelationTuple res rel subj

pRelationTuples :: Parser [ RelationTuple ]
pRelationTuples =
  do scnl
     many (pRelationTuple <* scnl)

-- * predicates

hasSubjectType :: ObjectType -> RelationTuple -> Bool
hasSubjectType st' (RelationTuple _ _ (Object st _)) = st == st'

hasSubject :: Object -> RelationTuple -> Bool
hasSubject subj (RelationTuple _ _ subj') = subj == subj'

hasResource :: Object -> RelationTuple -> Bool
hasResource res (RelationTuple res' _ _) = res == res'


-- * QuasiQuoters


objectExpr :: String -> Q Exp
objectExpr s =
  case runParser (sc *> pObject) s (T.pack s) of
    (Left e) -> error (errorBundlePretty e)
    (Right p) -> lift p

object :: QuasiQuoter
object = QuasiQuoter
  { quoteExp  = objectExpr
  , quotePat  = error "rel does not yet define an pattern quoter"
  , quoteType = error "rel does not yet define an type quoter"
  , quoteDec  = error "rel does not yet define a declaration quoter"
  }

relExpr :: String -> Q Exp
relExpr s =
  case runParser pRelation s (T.pack s) of
    (Left e) -> error (errorBundlePretty e)
    (Right p) -> lift p

rel :: QuasiQuoter
rel = QuasiQuoter
  { quoteExp  = relExpr
  , quotePat  = error "rel does not yet define an pattern quoter"
  , quoteType = error "rel does not yet define an type quoter"
  , quoteDec  = error "rel does not yet define a declaration quoter"
  }

relsExpr :: String -> Q Exp
relsExpr s =
  case runParser pRelationTuples s (T.pack s) of
    (Left e) -> error (errorBundlePretty e)
    (Right p) -> lift p

rels :: QuasiQuoter
rels = QuasiQuoter
  { quoteExp  = relsExpr
  , quotePat  = error "rels does not yet define an pattern quoter"
  , quoteType = error "rels does not yet define an type quoter"
  , quoteDec  = error "rels does not yet define a declaration quoter"
  }
