{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language OverloadedStrings #-}
module AccessControl.Relation where

import Data.Data (Data)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Text (Text)
import qualified Data.Text as T
import Data.Typeable (Typeable)
import Data.Void (Void)
import GHC.Generics
import Text.Megaparsec
import Text.Megaparsec.Char
import Text.PrettyPrint.HughesPJ (Doc, (<+>), ($$), ($+$))
import qualified Text.PrettyPrint.HughesPJ as PP
import qualified Text.Megaparsec.Char.Lexer as L -- (1)

-- FIXME: how does string escaping work?

ppText :: Text -> Doc
ppText t = PP.text (T.unpack t)

type Parser = Parsec Void Text

-- a name could be an object type, object id, relation name, etc.
pName :: Parser Text
pName = T.pack <$> some alphaNumChar

newtype Relation = Relation { unRelation :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

ppRelation :: Relation -> Doc
ppRelation (Relation r) = ppText r

pRelation :: Parser Relation
pRelation = Relation <$> pName

newtype ObjectType = ObjectType { unObjectType :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

ppObjectType :: ObjectType -> Doc
ppObjectType (ObjectType ty) = ppText ty

pObjectType :: Parser ObjectType
pObjectType = ObjectType <$> pName

newtype ObjectId = ObjectId { unObjectId :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

ppObjectId :: ObjectId -> Doc
ppObjectId (ObjectId i) = ppText i

pObjectId :: Parser ObjectId
pObjectId = ObjectId <$> pName

data Object = Object
  { objectType :: ObjectType
  , objectId   :: ObjectId
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

ppObject :: Object -> Doc
ppObject (Object ot oi) =
  ppObjectType ot <> PP.char ':' <> ppObjectId oi

pObject :: Parser Object
pObject =
  do ot <- pObjectType
     char ':'
     oi <- pObjectId
     pure $ Object ot oi

data RelationTuple = RelationTuple
  { resource :: Object
  , relation :: Relation
  , subject  :: Object
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)


ppRelationTuple :: RelationTuple -> Doc
ppRelationTuple (RelationTuple res rel subj) =
  ppObject res <> PP.char '#' <> ppRelation rel <> PP.char '@' <> ppObject subj

pRelationTuple :: Parser RelationTuple
pRelationTuple =
  do res <- pObject
     char '#'
     rel <- pRelation
     char '@'
     subj <- pObject
     pure $ RelationTuple res rel subj
