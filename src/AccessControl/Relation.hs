{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language FlexibleContexts #-}
{-# language FlexibleInstances #-}
{-# language MultiParamTypeClasses #-}
{-# language RankNTypes #-}
{-# language UndecidableInstances #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes, TemplateHaskell, DeriveLift #-}
{-# language DataKinds, KindSignatures, TypeFamilies, StandaloneDeriving #-}
module AccessControl.Relation where

-- import AccessControl.Schema (Permission(..), Relation(..), ToPermission(..), ToRelation(..), pName, pRelation, ppRelation, pObjectType, ppObjectType, ppText)
import Data.Data (Data)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Proxy (Proxy(..))
import Data.SafeCopy (SafeCopy(..), base)
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
-- it seems that authzed also allows / to appear in some names?
pName :: Parser Text
pName = T.pack <$> some (alphaNumChar <|> char '_' <|> char '/')


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

instance SafeCopy Relation where version = 1 ; kind = base

ppRelation :: Relation -> PP.Doc
ppRelation (Relation r) = ppText r

pRelation :: Parser Relation
pRelation = Relation <$> pName

-- * ObjectType

newtype ObjectType = ObjectType { unObjectType :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectType where version = 1 ; kind = base

ppObjectType :: ObjectType -> PP.Doc
ppObjectType (ObjectType ty) = ppText ty

pObjectType :: Parser ObjectType
pObjectType = ObjectType <$> pName

-- * SubjectId / ResourceId

-- An `SubjectId` identifies an subject within an `ObjectType` namespace
data SubjectId
  = SubjectId { unSubjectId :: Text }
  | SubjectWildcard
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy SubjectId where version = 1 ; kind = base

-- An `ResourceId` identifies an resource within an `ObjectType` namespace
data ResourceId = ResourceId { unResourceId :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ResourceId where version = 1 ; kind = base

class PpObjectId a where
  ppObjectId :: a -> Doc

instance PpObjectId SubjectId where
  ppObjectId (SubjectId i) = ppText i
  ppObjectId SubjectWildcard = PP.char '*'

instance PpObjectId ResourceId where
  ppObjectId (ResourceId i) = ppText i

class PObjectId (knd :: ObjectKind) where
  pObjectId :: forall (proxy :: ObjectKind -> *). proxy knd  -> Parser (ToObjectId knd)

instance PObjectId SubjectK where
  pObjectId _ =
    do char '*'
       pure SubjectWildcard
    <|>
       SubjectId <$> pName

instance PObjectId ResourceK where
  pObjectId p =
       ResourceId <$> pName

-- * Object

data ObjectKind
  = SubjectK
  | ResourceK
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectKind where version = 1 ; kind = base

type family ToObjectId (a :: ObjectKind) where
            ToObjectId SubjectK  = SubjectId
            ToObjectId ResourceK = ResourceId

class KnownObjectKind (knd :: ObjectKind) where
  knownObjectKind :: proxy knd -> ObjectKind

instance KnownObjectKind SubjectK where
  knownObjectKind _ = SubjectK

instance KnownObjectKind ResourceK where
  knownObjectKind _ = ResourceK

-- | An 'Object' has an 'ObjectType' and 'ObjectId'.
--
-- An 'Object' identifies a resource or subject.
--
-- The 'ObjectId' is unique for an particular 'ObjectType' but not across all 'ObjectTypes'.
data Object (knd :: ObjectKind) = Object
  { objectType :: ObjectType
  , objectId   :: ToObjectId knd
  }
--  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

deriving instance Eq (Object SubjectK)
deriving instance Eq (Object ResourceK)
deriving instance Ord (Object SubjectK)
deriving instance Ord (Object ResourceK)
deriving instance Read (Object SubjectK)
deriving instance Read (Object ResourceK)
deriving instance Show (Object SubjectK)
deriving instance Show (Object ResourceK)
deriving instance Data (Object SubjectK)
deriving instance Data (Object ResourceK)
deriving instance Typeable (Object SubjectK)
deriving instance Typeable (Object ResourceK)
deriving instance Generic (Object SubjectK)
deriving instance Generic (Object ResourceK)
deriving instance Lift (Object SubjectK)
deriving instance Lift (Object ResourceK)


instance SafeCopy (Object SubjectK)  where version = 1 ; kind = base
instance SafeCopy (Object ResourceK) where version = 1 ; kind = base

class ToObject a where
  toObjectType   :: a -> ObjectType
  toObjectIdText :: a -> Text
  toSubject :: a -> Object SubjectK
  toSubject a = Object (toObjectType a) (SubjectId (toObjectIdText a))
  toResource :: a -> Object ResourceK
  toResource a = Object (toObjectType a) (ResourceId (toObjectIdText a))

instance ToObject (Object SubjectK) where
  toObjectType (Object ot _) = ot
  toObjectIdText (Object _ oi) =
    case oi of
      SubjectWildcard -> "*"
      SubjectId i     -> i
  toSubject o = o
  toResource (Object ot oi) =
    case oi of
      SubjectWildcard -> error "cannot cast to ResourceId"
      SubjectId i -> Object ot (ResourceId i)

ppObject :: (PpObjectId (ToObjectId knd)) => Object (knd :: ObjectKind) -> Doc
ppObject (Object ot oi) =
  ppObjectType ot <> PP.char ':' <> ppObjectId oi


pObject :: (PObjectId knd) => proxy (knd :: ObjectKind) -> Parser (Object (knd :: ObjectKind))
pObject p =
  do ot <- pObjectType
     char ':'
     oi <- pObjectId p
     pure $ Object ot oi

pSubject :: Parser (Object SubjectK)
pSubject = pObject Proxy

pResource :: Parser (Object ResourceK)
pResource = pObject Proxy

{-
-- * RelationTuple
-}
-- | Define a relationship between a 'resource' and 'subject'
data RelationTuple = RelationTuple
  { resource        :: Object ResourceK
  , relation        :: Relation
  , subject         :: Object SubjectK
  , subjectRelation :: Maybe Relation
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy RelationTuple where version = 1 ; kind = base

{-
toRelationTuple :: (KnownPermission resource relation subject, ToObject resource, ToRelation relation, ToObject subject) => resource -> relation -> subject -> RelationTuple
toRelationTuple resource relation subject = RelationTuple (toObject resource) (toRelation relation) (toObject subject)
-}
ppMaybeRelation :: Maybe Relation -> Doc
ppMaybeRelation Nothing = PP.empty
ppMaybeRelation (Just rel) = PP.char '#' <> ppRelation rel

ppRelationTuple :: RelationTuple -> Doc
ppRelationTuple (RelationTuple res rel subj mSubRelation) =
  ppObject res <> PP.char '#' <> ppRelation rel <> PP.char '@' <> ppObject subj <> ppMaybeRelation mSubRelation

ppRelationTuples :: [RelationTuple] -> Doc
ppRelationTuples rt =
  PP.vcat $ map ppRelationTuple rt

pRelationTuple :: Parser RelationTuple
pRelationTuple =
  do res <- pResource
     char '#'
     rel <- pRelation
     char '@'
     subj <- pSubject
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

hasSubject :: Object SubjectK -> RelationTuple -> Bool
hasSubject subj (RelationTuple _ _ subj' _) = subj == subj'

hasResource :: Object ResourceK -> RelationTuple -> Bool
hasResource res (RelationTuple res' _ _ _) = res == res'

hasRelation :: Relation -> RelationTuple -> Bool
hasRelation rel (RelationTuple _ rel' _ _) = rel == rel'

-- * QuasiQuoters

objectExpr :: (PObjectId knd, Lift (Object knd)) => proxy (knd :: ObjectKind) -> String -> Q Exp
objectExpr p s =
  case runParser (sc *> pObject p) s (T.pack s) of
    (Left e) -> error (errorBundlePretty e)
    (Right p) -> lift p

subj :: QuasiQuoter
subj = QuasiQuoter
  { quoteExp  = objectExpr (Proxy :: Proxy SubjectK)
  , quotePat  = error "subj does not yet define an pattern quoter"
  , quoteType = error "subj does not yet define an type quoter"
  , quoteDec  = error "subj does not yet define a declaration quoter"
  }

res :: QuasiQuoter
res = QuasiQuoter
  { quoteExp  = objectExpr (Proxy :: Proxy ResourceK)
  , quotePat  = error "res does not yet define an pattern quoter"
  , quoteType = error "res does not yet define an type quoter"
  , quoteDec  = error "res does not yet define a declaration quoter"
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
  toObjectType (UserId n)   = ObjectType "user"
  toObjectIdText (UserId n) = T.pack $ show n

instance ToObject (Maybe UserId) where
  toObjectType _ = ObjectType "user"
  toObjectIdText (Just (UserId n)) = T.pack $ show n
  toObjectIdText Nothing           = "anonymous"


