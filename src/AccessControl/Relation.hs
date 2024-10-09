{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language FlexibleInstances #-}
{-# language MultiParamTypeClasses #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes, TemplateHaskell, DeriveLift #-}
module AccessControl.Relation where

-- import AccessControl.Schema (Permission(..), Relation(..), ToPermission(..), ToRelation(..), pName, pRelation, ppRelation, pObjectType, ppObjectType, ppText)
import Data.Data (Data)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.SafeCopy (SafeCopy)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Typeable (Typeable)
import Data.UserId (UserId(..))
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

-- import AccessControl.Schema (ObjectType(..),sc, scnl) -- for Lift Text instance

-- FIXME: how does string escaping work?


instance Lift Text where
  lift t = lift (T.unpack t)


type Parser = Parsec Void Text

-- fixme: a more strict parser might only allow [a-z][a-z0-9_]{1,62}[a-z0-9]
pName :: Parser Text
pName = T.pack <$> some (alphaNumChar <|> char '_')


ppText :: Text -> PP.Doc
ppText t = PP.text (T.unpack t)

sc :: Parser ()
sc = L.space
  hspace1
  (L.skipLineComment "#")
  (L.skipBlockComment "/*" "*/")

scnl :: Parser ()
scnl = L.space
  space1
  (L.skipLineComment "#")
  (L.skipBlockComment "/*" "*/")

-- * Relation

-- | a name could be an object type, object id, relation name, etc.
-- in something like 'group:123#member', this is just the 'member' part.
-- fixme: this should use a smart constructor to ensure that the `Text` value only contains valid symbols.
newtype Relation = Relation { unRelation :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

class ToRelation a where
  toRelation :: a -> Relation

instance ToRelation Relation where
  toRelation = id

instance SafeCopy Relation

ppRelation :: Relation -> PP.Doc
ppRelation (Relation r) = ppText r

pRelation :: Parser Relation
pRelation = Relation <$> pName

-- * ObjectType

newtype ObjectType = ObjectType { unObjectType :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectType

ppObjectType :: ObjectType -> PP.Doc
ppObjectType (ObjectType ty) = ppText ty

pObjectType :: Parser ObjectType
pObjectType = ObjectType <$> pName

-- * ObjectId

-- An `ObjectId` identifies an object within an `ObjectType` namespace
newtype ObjectId = ObjectId { unObjectId :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectId

ppObjectId :: ObjectId -> Doc
ppObjectId (ObjectId i)   = ppText i
-- ppObjectId ObjectWildcard = PP.char '*'

pObjectId :: Parser ObjectId
pObjectId =
--   do char '*'
--     pure ObjectWildcard
--  <|>
     ObjectId <$> pName

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
  { resource        :: Object
  , relation        :: Relation
  , subject         :: Object
  , subjectRelation :: Maybe Relation
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy RelationTuple

{-
toRelationTuple :: (KnownPermission resource relation subject, ToObject resource, ToRelation relation, ToObject subject) => resource -> relation -> subject -> RelationTuple
toRelationTuple resource relation subject = RelationTuple (toObject resource) (toRelation relation) (toObject subject)
-}
ppRelationTuple :: RelationTuple -> Doc
ppRelationTuple (RelationTuple res rel subj mSubRelation) =
  ppObject res <> PP.char '#' <> ppRelation rel <> PP.char '@' <> ppObject subj <> ppMaybeRelation mSubRelation

ppMaybeRelation :: Maybe Relation -> Doc
ppMaybeRelation Nothing = PP.empty
ppMaybeRelation (Just rel) = PP.char '#' <> ppRelation rel

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
     mSubRelation <- optional $
       do char '#'
          pRelation
     pure $ RelationTuple res rel subj mSubRelation

pRelationTuples :: Parser [ RelationTuple ]
pRelationTuples =
  do scnl
     many (pRelationTuple <* scnl)

-- * predicates

hasSubjectType :: ObjectType -> RelationTuple -> Bool
hasSubjectType st' (RelationTuple _ _ (Object st _) _) = st == st'

hasSubject :: Object -> RelationTuple -> Bool
hasSubject subj (RelationTuple _ _ subj' _) = subj == subj'

hasResource :: Object -> RelationTuple -> Bool
hasResource res (RelationTuple res' _ _ _) = res == res'

hasRelation :: Relation -> RelationTuple -> Bool
hasRelation rel (RelationTuple _ rel' _ _) = rel == rel'

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

instance ToObject UserId where
  toObject (UserId n) = Object (ObjectType "user") (ObjectId $ T.pack $ show n)

instance ToObject (Maybe UserId) where
  toObject (Just (UserId n)) = Object (ObjectType "user") (ObjectId $ T.pack $ show n)
  toObject Nothing           = Object (ObjectType "user") (ObjectId $ "anonymous")
