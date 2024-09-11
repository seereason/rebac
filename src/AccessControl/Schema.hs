{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes, TemplateHaskell, DeriveLift #-}
{-# language StandaloneDeriving #-}
module AccessControl.Schema where

import Data.Data (Data)
import Data.Either (lefts, rights)
import Data.SafeCopy (SafeCopy)
import Data.List (intersperse, find)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (catMaybes, isJust)
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
import Text.Megaparsec.Error
import Text.PrettyPrint.HughesPJ ((<+>), ($$), ($+$))
import qualified Text.PrettyPrint.HughesPJ as PP
import qualified Text.Megaparsec.Char.Lexer as L -- (1)

instance Lift Text where
  lift t = lift (T.unpack t)

-- instance (Lift a) => Lift (NonEmpty a) where
--  lift _ = undefined

deriving instance (Lift a) => Lift (NonEmpty a)

ppText :: Text -> PP.Doc
ppText t = PP.text (T.unpack t)

-- a name could be an object type, object id, relation name, etc.
-- pName :: Parser Text
-- pName = T.pack <$> some alphaNumChar

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

newtype Permission = Permission { unPermission :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy Permission

class ToPermission a where
  toPermission :: a -> Permission

instance ToPermission Permission where
  toPermission = id

ppPermission :: Permission -> PP.Doc
ppPermission (Permission r) = ppText r

pPermission :: Parser Permission
pPermission = Permission <$> pName

ppPermissionRelation :: Either Permission Relation -> PP.Doc
ppPermissionRelation (Left p)  = ppPermission p
ppPermisisonRelation (Right r) = ppRelation r

data Comment
  = SingleLineComment Text
  | MultiLineComment [ Text ]
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

newtype ObjectType = ObjectType { unObjectType :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectType

ppObjectType :: ObjectType -> PP.Doc
ppObjectType (ObjectType ty) = ppText ty

pObjectType :: Parser ObjectType
pObjectType = ObjectType <$> pName

data ObjectRelation = ObjectRelation
  { orName :: Text
  , orObjectTypes :: NonEmpty TypeReference
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectRelation

data ResourceId
  = ResourceId Text
  | Wildcard
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ResourceId

data Resource = Resource
  { resourceType :: Text
  , resourceId   :: Maybe ResourceId
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy Resource

data Subject = Subject
  { subjectType :: Text
  , subjectId   :: Maybe Text
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy Subject

data TypeReference = TypeReference
  { objectResource :: Resource
  , objectRelation :: Maybe Text
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy TypeReference

data PermissionExpression
  = Union        PermissionExpression PermissionExpression
  | Intersection PermissionExpression PermissionExpression
  | Exclusion    PermissionExpression PermissionExpression
  | Arrow        Relation Text
  | Ref          TypeReference
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy PermissionExpression

data ObjectPermission = ObjectPermission
  { opName :: Text
  , opExpr :: PermissionExpression
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectPermission

-- does not preserve comments or whitespace
--
-- A definition has a name and a list of relations and permissions
data Definition = Definition
  { defName  :: Text
  , defDecls :: [ Either ObjectRelation ObjectPermission ]
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)
instance SafeCopy Definition

objectRelations :: Definition -> [ ObjectRelation ]
objectRelations def = lefts (defDecls def)

data Schema = Schema
  { definitions :: [ Definition ]
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy Schema

knownObjectTypes :: Schema -> [ ObjectType ]
knownObjectTypes (Schema defs) = map (ObjectType . defName) defs

knownRelations :: Schema -> [ Relation ]
knownRelations (Schema defs) = concatMap (map rel . objectRelations) defs
  where
    rel :: ObjectRelation -> Relation
    rel or = Relation (orName or)

-- * Predicates

knownObjectType :: Schema -> ObjectType -> Bool
knownObjectType (Schema defs) (ObjectType ot) =
  isJust $ find (\d -> defName d == ot) defs

-- * Printers

ppResource :: Resource -> PP.Doc
ppResource (Resource n mId) =
  PP.text (T.unpack n) <> (case mId of
                             Nothing -> PP.empty
                             (Just (ResourceId i)) -> PP.char ':' <> PP.text (T.unpack i))

ppTypeReference :: TypeReference -> PP.Doc
ppTypeReference (TypeReference r mRel) =
  ppResource r <> (case mRel of
                     Nothing -> PP.empty
                     (Just rel) -> PP.char '#' <> PP.text (T.unpack rel))

ppPermissionExpression :: PermissionExpression -> PP.Doc
ppPermissionExpression (Union a b)        = ppPermissionExpression a <+> PP.char '+' <+> ppPermissionExpression b
ppPermissionExpression (Intersection a b) = ppPermissionExpression a <+> PP.char '&' <+> ppPermissionExpression b
ppPermissionExpression (Exclusion a b)    = ppPermissionExpression a <+> PP.char '-' <+> ppPermissionExpression b
ppPermissionExpression (Arrow rel pr)     = ppRelation rel <> PP.text "->" <> ppText pr
ppPermissionExpression (Ref tr)           = ppTypeReference tr

ppObjectPermission :: ObjectPermission -> PP.Doc
ppObjectPermission (ObjectPermission nm exp) =
  PP.text "permission" <+> PP.text (T.unpack nm) <+> PP.char '=' <+> ppPermissionExpression exp

ppTypeReferences :: NonEmpty TypeReference -> PP.Doc
ppTypeReferences refs = PP.hsep $ PP.punctuate (PP.text " |")  (map ppTypeReference (NonEmpty.toList refs))

ppObjectRelation :: ObjectRelation -> PP.Doc
ppObjectRelation (ObjectRelation nm refs) =
  PP.text "relation" <+> (PP.text (T.unpack nm) <> PP.char ':') <+> ppTypeReferences refs

ppDef :: Either ObjectRelation ObjectPermission -> PP.Doc
ppDef (Left or) = ppObjectRelation or
ppDef (Right op) = ppObjectPermission op

ppDefinition :: Definition -> PP.Doc
ppDefinition (Definition nm []) = (PP.text "definition" <+> (PP.text (T.unpack nm)) <+> PP.text "{}")
ppDefinition (Definition nm decls) =
  (PP.text "definition" <+> (PP.text (T.unpack nm)) <+> PP.char '{') $$ (PP.nest 4 $ PP.vcat (map ppDef decls)) $$ PP.char '}'

ppSchema :: Schema -> PP.Doc
ppSchema (Schema defs) =
  PP.vcat $ intersperse (PP.text "") (map ppDefinition defs)

-- * Parser

type Parser = Parsec Void Text

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

lexeme :: Parser a -> Parser a
lexeme = L.lexeme sc

symbol :: Text -> Parser Text
symbol = L.symbol sc

-- fixme: a more strict parser might only allow [a-z][a-z0-9_]{1,62}[a-z0-9]
pName :: Parser Text
pName = T.pack <$> some (alphaNumChar <|> char '_')

lcurlyBrace :: Parser Char
lcurlyBrace = char '{'

rcurlyBrace :: Parser Char
rcurlyBrace = char '}'

pResourceId :: Parser ResourceId
pResourceId =
  do char '*'
     pure Wildcard
  <|>
  do i <- lexeme pName
     pure (ResourceId i)

test_pResourceId :: IO ()
test_pResourceId =
  do parseTest pResourceId "*"
     parseTest pResourceId "foo"

pResource :: Parser Resource
pResource =
  do rn <- lexeme pName
     rid <- optional $ do char ':'
                          pResourceId
     pure (Resource rn rid)

test_pResource :: IO ()
test_pResource =
  do parseTest pResource "foo"
     parseTest pResource "foo:bar"
     parseTest pResource "foo:*"

pTypeReference :: Parser TypeReference
pTypeReference =
  do r <- pResource
     mRel <- optional $ do char '#'
                           lexeme pName
     pure (TypeReference r mRel)

test_pTypeReference :: IO ()
test_pTypeReference =
  do parseTest pTypeReference "foo"
     parseTest pTypeReference "foo:fooid"
     parseTest pTypeReference "foo:fooid#rel"
     parseTest pTypeReference "foo:*#rel"
     parseTest pTypeReference "foo#rel"

pTypeReferences :: Parser (NonEmpty TypeReference)
pTypeReferences =
  do NonEmpty.fromList <$> (pTypeReference `sepBy` (lexeme $ char '|'))

test_pTypeReferences :: IO ()
test_pTypeReferences =
  do parseTest pTypeReferences "foo"
     parseTest pTypeReferences "foo | bar:*#rel"

pObjectRelation :: Parser ObjectRelation
pObjectRelation =
  do try (sc *> symbol "relation")
     relName <- lexeme pName
     char ':'
     sc
     refs <- pTypeReferences
     pure (ObjectRelation relName refs)

test_pObjectRelation :: IO ()
test_pObjectRelation =
  do parseTest pObjectRelation "relation writer: user | user:admin#foo"


-- fixme: add support for parens
pPermissionExpression :: Parser PermissionExpression
pPermissionExpression =
  do let pArrow = try $
           do rel <- pRelation
              string "->"
              pr <- pName
              pure (Arrow rel pr)
     a <- pArrow <|> (Ref <$> pTypeReference)
     mop <- optional $ satisfy (\c -> c `elem` ("+&-" :: [Char]))
     case mop of
       Nothing -> pure a
       (Just op) ->
         do sc
            b <- pPermissionExpression
            case op of
              '+' -> pure $ Union        a b
              '&' -> pure $ Intersection a b
              '-' -> pure $ Exclusion    a b
              _   -> error "this is not my beautiful house"

test_pPermissionExpression =
  do parseTest pPermissionExpression "writer"
     parseTest pPermissionExpression "writer + reader"

pObjectPermission :: Parser ObjectPermission
pObjectPermission =
  do try (sc *> symbol "permission")
     nm <- lexeme pName
     lexeme (char '=')
     expr <- pPermissionExpression
     pure (ObjectPermission nm expr)

pDef :: Parser (Either ObjectRelation ObjectPermission)
pDef = (Left <$> pObjectRelation) <|> (Right <$> pObjectPermission)

pDefinition :: Parser Definition
pDefinition =
  do try (sc *> symbol "definition")
     n <- lexeme pName
     lcurlyBrace
     scnl
     defs <- manyTill (pDef <* scnl)  rcurlyBrace
     pure (Definition n defs)

test_pDefinition :: IO ()
test_pDefinition =
  do parseTest pDefinition "definition user {}"
     parseTest pDefinition $ "definition user {relation writer: user\nrelation reader: user}"
     parseTest pDefinition $ "definition user {relation writer: user\nrelation reader: user\n permission edit = writer}"

pSchema :: Parser Schema
pSchema =
  do scnl
     defs <- many (pDefinition <* scnl)
     pure $ Schema defs

test_pSchema :: IO ()
test_pSchema =
  do let res = runParser pSchema "" (T.unlines [ "\ndefinition user {}"
                                               , "definition user {relation writer: user\nrelation reader: user\n}"
                                               , "definition user {relation writer: user\nrelation reader: user\n permission edit = writer\n permission view = writer + reader }\n\n"
                                               ])
     case res of
       (Right s) -> print $ ppSchema s
       (Left e) -> putStrLn $ errorBundlePretty e

schemaExpr :: String -> Q Exp
schemaExpr s =
  case runParser pSchema s (T.pack s) of
    (Left e) -> error (errorBundlePretty e)
    (Right p) -> lift p

schema :: QuasiQuoter
schema = QuasiQuoter
  { quoteExp  = schemaExpr
  , quotePat  = error "schema does not yet define an pattern quoter"
  , quoteType = error "schema does not yet define an type quoter"
  , quoteDec  = error "schema does not yet define a declaration quoter"
  }
