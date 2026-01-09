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
import Data.Char (isSpace)
import Data.Data (Data)
import Data.Either (either)
import Data.Fixed  (Fixed(MkFixed), Pico)
import Data.Functor (void)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Proxy (Proxy(..))
import Data.SafeCopy (SafeCopy(..), base)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock (NominalDiffTime(..), UTCTime)
import Data.Time.Clock.POSIX (POSIXTime, utcTimeToPOSIXSeconds, posixSecondsToUTCTime)
import Data.Time.Format (parseTimeM, defaultTimeLocale, formatTime, iso8601DateFormat)
import Data.Typeable (Typeable)
import Data.UserId (UserId(..))
import Data.Void (Void)
import GHC.Generics
import Instances.TH.Lift () -- Lift Text instance
import Language.Haskell.TH
import Language.Haskell.TH.Quote
import Language.Haskell.TH.Syntax
import Language.Haskell.TH.Lib (tupleT)
import Text.Megaparsec
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer as L
import Text.PrettyPrint.HughesPJ (Doc, (<+>), ($$), ($+$))
import qualified Text.PrettyPrint.HughesPJ as PP

-- import AccessControl.Schema (ObjectType(..),sc, scnl) -- for Lift Text instance

-- FIXME: how does string escaping work?

type Parser = Parsec Void Text

-- fixme: a more strict parser might only allow [a-z][a-z0-9_]{1,62}[a-z0-9]
-- it seems that authzed also allows / to appear in some names?
pName :: Parser Text
pName = T.pack <$> some (alphaNumChar <|> char '_' <|> char '/')


ppText :: Text -> PP.Doc
ppText t = PP.text (T.unpack t)

sc :: Parser ()
sc = L.space
  (void $ takeWhile1P (Just "white space") isHSpace) -- this is hspace1 but that was not added until 9.0
  (L.skipLineComment "#")
  (L.skipBlockComment "/*" "*/")
  where
    -- | Is it a horizontal space character?
    isHSpace :: Char -> Bool
    isHSpace x = isSpace x && x /= '\n' && x /= '\r'

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

-- * ObjectWildcard

-- | used to track if an ObjectId can be a wildcard or not
data ObjectWildcard
  = AllowWildcard
  | NoWildcard
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectWildcard where version = 1 ; kind = base

data WildcardObjectId
  = Specific ObjectId
  | Wildcard
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy WildcardObjectId where version = 1 ; kind = base

type family ToObjectId (a :: ObjectWildcard) where
            ToObjectId NoWildcard    = ObjectId
            ToObjectId AllowWildcard = WildcardObjectId

class KnownObjectWildcard (knd :: ObjectWildcard) where
  knownObjectWildcard :: proxy knd -> ObjectWildcard

instance KnownObjectWildcard AllowWildcard where
  knownObjectWildcard _ = AllowWildcard

instance KnownObjectWildcard NoWildcard where
  knownObjectWildcard _ = NoWildcard

toNoWildcard :: Object AllowWildcard -> Maybe (Object NoWildcard)
toNoWildcard (Object ot (Specific oi)) = Just (Object ot oi)
toNoWildcard (Object ot Wildcard)      = Nothing

toWildcard :: Object NoWildcard -> Object AllowWildcard
toWildcard (Object ot oi) = Object ot (Specific oi)

-- * ObjectType

newtype ObjectType = ObjectType { unObjectType :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectType where version = 1 ; kind = base

ppObjectType :: ObjectType -> PP.Doc
ppObjectType (ObjectType ty) = ppText ty

pObjectType :: Parser ObjectType
pObjectType = ObjectType <$> pName

-- * ObjectId

-- An `SubjectId` identifies an subject within an `ObjectType` namespace
newtype ObjectId
  = ObjectId { unObjectId :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectId where version = 1 ; kind = base

-- ppObjectId :: ObjectId -> Doc
-- ppObjectId (ObjectId i) = ppText i

-- pObjectId :: Parser ObjectId
-- pObjectId = ObjectId <$> pName

{-
-- An `ResourceId` identifies an resource within an `ObjectType` namespace
data ResourceId = ResourceId { unResourceId :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ResourceId where version = 1 ; kind = base
-}
class PpObjectId a where
  ppObjectId :: a -> Doc

instance PpObjectId WildcardObjectId where
  ppObjectId (Specific i) = ppObjectId i
  ppObjectId Wildcard = PP.char '*'

instance PpObjectId ObjectId where
  ppObjectId (ObjectId i) = ppText i

class PObjectId (knd :: ObjectWildcard) where
  pObjectId :: forall (proxy :: ObjectWildcard -> *). proxy knd  -> Parser (ToObjectId knd)

instance PObjectId AllowWildcard where
  pObjectId _ =
    do char '*'
       pure Wildcard
    <|>
       Specific <$> pObjectId (Proxy :: Proxy NoWildcard)

instance PObjectId NoWildcard where
  pObjectId p =
       ObjectId <$> pName

-- * Object

-- | An 'Object' has an 'ObjectType' and 'ObjectId'.
--
-- An 'Object' identifies a resource or subject.
--
-- The 'ObjectId' is unique for an particular 'ObjectType' but not across all 'ObjectTypes'.
data Object (knd :: ObjectWildcard) = Object
  { objectType :: ObjectType
  , objectId   :: ToObjectId knd
  }
--  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

deriving instance Eq (Object AllowWildcard)
deriving instance Eq (Object NoWildcard)
deriving instance Ord (Object AllowWildcard)
deriving instance Ord (Object NoWildcard)
deriving instance Read (Object AllowWildcard)
deriving instance Read (Object NoWildcard)
deriving instance Show (Object AllowWildcard)
deriving instance Show (Object NoWildcard)
deriving instance Data (Object AllowWildcard)
deriving instance Data (Object NoWildcard)
deriving instance Typeable (Object AllowWildcard)
deriving instance Typeable (Object NoWildcard)
deriving instance Generic (Object AllowWildcard)
deriving instance Generic (Object NoWildcard)
deriving instance Lift (Object AllowWildcard)
deriving instance Lift (Object NoWildcard)

instance SafeCopy (Object AllowWildcard)  where version = 1 ; kind = base
instance SafeCopy (Object NoWildcard) where version = 1 ; kind = base

class ToObject a where
--   toObjectType   :: a -> ObjectType
--  toObjectIdText :: a -> Text
  toObject       :: a -> Object NoWildcard
--  toObject a = Object (toObjectType a) (ObjectId (toObjectIdText a))
{- 
  toSubject :: a -> Object SubjectK
  toSubject a = Object (toObjectType a) (SubjectId (toObjectIdText a))
  toResource :: a -> Object NoWildcard
  toResource a = Object (toObjectType a) (ResourceId (toObjectIdText a))
-}
instance ToObject (Object NoWildcard) where
  toObject o = o
{-
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
-}
ppObject :: (PpObjectId (ToObjectId knd)) => Object (knd :: ObjectWildcard) -> Doc
ppObject (Object ot oi) =
  ppObjectType ot <> PP.char ':' <> ppObjectId oi


pObject' :: (PObjectId knd) => proxy (knd :: ObjectWildcard) -> Parser (Object knd)
pObject' p =
  do ot <- pObjectType
     char ':'
     oi <- pObjectId p
     pure $ Object ot oi

pObject :: Parser (Object NoWildcard)
pObject = pObject' Proxy

pObjectWild :: Parser (Object AllowWildcard)
pObjectWild = pObject' Proxy

instance ToObject UserId where
  toObject (UserId n)   = Object (ObjectType "user") (ObjectId (T.pack $ show n))

instance ToObject (Maybe UserId) where
  toObject (Just (UserId n)) = Object (ObjectType "user") (ObjectId (T.pack $ show n))
  toObject Nothing           = Object (ObjectType "user") (ObjectId "anonymous")


-- * RelationTuple and friends

newtype Tag = Tag { unTag :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy Tag where version = 1 ; kind = base

-- ** Expiration is a hack to get around the fact that we need to upgrade `time-1.15` before we have a `Lift` instance for `POSIXTime`

newtype Expiration = Expiration { unExpiration :: Integer }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy Expiration where version = 1 ; kind = base

posixTimeToExpiration :: POSIXTime -> Expiration
posixTimeToExpiration time =
  let (MkFixed i) = ((realToFrac time) :: Pico)
  in Expiration i

expirationToPOSIXTime :: Expiration -> POSIXTime
expirationToPOSIXTime (Expiration i) =
  realToFrac ((MkFixed i) :: Pico)

formatExpiration :: Expiration -> String
formatExpiration t = formatTime defaultTimeLocale (iso8601DateFormat (Just "%H:%M:%SZ")) (posixSecondsToUTCTime (expirationToPOSIXTime t))

parseExpiration :: String -> Maybe Expiration
parseExpiration timeStr =
  case parseTimeM True defaultTimeLocale (iso8601DateFormat (Just "%H:%M:%SZ")) timeStr of
    Nothing  -> Nothing
    (Just t) -> Just $ posixTimeToExpiration (utcTimeToPOSIXSeconds t)


-- | Define a relationship between a 'resource' and 'subject'
data RelationTuple = RelationTuple
  { resource        :: Object NoWildcard
  , relation        :: Relation
  , subject         :: Object AllowWildcard
  , subjectRelation :: Maybe Relation
  , tag             :: Maybe Tag
  , expiration      :: Maybe Expiration
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
ppRelationTuple (RelationTuple res rel subj mSubRelation mTag mExpiration) =
  ppObject res <> PP.char '#' <> ppRelation rel <> PP.char '@' <> ppObject subj <> ppMaybeRelation mSubRelation <> ppMaybeTag mTag <> ppMaybeExpiration mExpiration

ppMaybeTag :: Maybe Tag -> Doc
ppMaybeTag Nothing = PP.empty
ppMaybeTag (Just (Tag txt)) = PP.char '%' <> ppText txt

ppMaybeExpiration :: Maybe Expiration -> Doc
ppMaybeExpiration Nothing = PP.empty
ppMaybeExpiration (Just t) = PP.text $ "[expiration:" ++ (formatTime defaultTimeLocale (iso8601DateFormat (Just "%H:%M:%SZ")) (posixSecondsToUTCTime (expirationToPOSIXTime t))) ++ "]"

-- for now this only allows [a-z][a-z0-9_]{1,62}[a-z0-9]
pTag :: Parser Tag
pTag =
  do char '%'
     t <- pName
     pure (Tag t)

pExpiration :: Parser Expiration
pExpiration =
  do string "[expiration:"
     time <- try $ do timeStr <- some (digitChar <|> char ':' <|> char '-' <|> char 'T' <|> char 'Z')
                      case parseTimeM True defaultTimeLocale (iso8601DateFormat (Just "%H:%M:%SZ")) timeStr of
                        (Just t) -> pure (t :: UTCTime)
                        Nothing -> fail $ "could not parse "++ timeStr


     char ']'
     pure (posixTimeToExpiration (utcTimeToPOSIXSeconds time))

ppRelationTuples :: [RelationTuple] -> Doc
ppRelationTuples rt =
  PP.vcat $ map ppRelationTuple rt

pRelationTuple :: Parser RelationTuple
pRelationTuple =
  do res <- pObject
     char '#'
     rel <- pRelation
     char '@'
     subj <- pObjectWild
     mSubRelation <- optional $
       do char '#'
          pRelation
     mTag <- optional pTag
     mExpiration <- optional pExpiration
     pure $ RelationTuple res rel subj mSubRelation mTag mExpiration

-- alas, `mapLeft` would be nice here, but I am not adding a dependency just for that
parseRelationTuple :: Text -> Either String RelationTuple
parseRelationTuple t =
  case runParser pRelationTuple "" t of
    Left e   -> Left $ errorBundlePretty e
    Right rt -> Right rt

pRelationTuples :: Parser [ RelationTuple ]
pRelationTuples =
  do scnl
     many (pRelationTuple <* scnl)

-- * simple predicates

hasSubjectType :: ObjectType -> RelationTuple -> Bool
hasSubjectType st' (RelationTuple _ _ (Object st _) _ _ _) = st == st'

hasSubject :: Object AllowWildcard -> RelationTuple -> Bool
hasSubject subj (RelationTuple _ _ subj' _ _ _) = subj == subj'

hasResourceType :: ObjectType -> RelationTuple -> Bool
hasResourceType rt' (RelationTuple (Object rt _) _ _ _ _ _) = rt == rt'

hasResource :: Object NoWildcard -> RelationTuple -> Bool
hasResource res (RelationTuple res' _ _ _ _ _) = res == res'

hasRelation :: Relation -> RelationTuple -> Bool
hasRelation rel (RelationTuple _ rel' _ _ _ _) = rel == rel'

hasTag :: Tag -> RelationTuple -> Bool
hasTag tag (RelationTuple _ _ _ _ mTag _) = (Just tag) == mTag

-- hasTag :: Tag -> RelationTuple -> Bool

-- * QuasiQuoters

objectExpr :: (PObjectId knd, Lift (Object knd)) => proxy (knd :: ObjectWildcard) -> String -> Q Exp
objectExpr p s =
  case runParser (sc *> pObject' p) s (T.pack s) of
    (Left e) -> error (errorBundlePretty e)
    (Right p) -> lift p

object :: QuasiQuoter
object = QuasiQuoter
  { quoteExp  = objectExpr (Proxy :: Proxy NoWildcard)
  , quotePat  = error "subj does not yet define an pattern quoter"
  , quoteType = error "subj does not yet define an type quoter"
  , quoteDec  = error "subj does not yet define a declaration quoter"
  }

objectW :: QuasiQuoter
objectW = QuasiQuoter
  { quoteExp  = objectExpr (Proxy :: Proxy AllowWildcard)
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

