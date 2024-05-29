{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language OverloadedStrings #-}
module AccessControl.Schema where

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
import Text.PrettyPrint.HughesPJ ((<+>), ($$), ($+$))
import qualified Text.PrettyPrint.HughesPJ as PP
import qualified Text.Megaparsec.Char.Lexer as L -- (1)

-- data Schema = Schema
--  {
{-
newtype Relation = Relation { unRelation :: Text }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data RelationTuple = RelationTuple
  { object   :: Object
  , relation :: Relation
  , user     :: User
  }
-}

data Comment
  = SingleLineComment Text
  | MultiLineComment [ Text ]
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

newtype ObjectType = ObjectType { unObjectType :: Text } deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data ObjectRelation = ObjectRelation
  { orName :: Text
  , orObjectTypes :: NonEmpty TypeReference
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data ResourceId
  = ResourceId Text
  | Wildcard
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data Resource = Resource
  { resourceType :: Text
  , resourceId   :: Maybe ResourceId
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data Subject = Subject
  { subjectType :: Text
  , subjectId   :: Maybe Text
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data TypeReference = TypeReference
  { objectResource :: Resource
  , objectRelation :: Maybe Text
  }  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)


data PermissionExpression
  = Union        PermissionExpression PermissionExpression
  | Intersection PermissionExpression PermissionExpression
  | Exclusion    PermissionExpression PermissionExpression
  | Arrow        Text Text
  | Ref          TypeReference
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

data ObjectPermission = ObjectPermission
  { opName :: Text
  , opExpr :: PermissionExpression
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

-- does not preserve comments or whitespace
data Definition = Definition
  { defName  :: Text
  , defDecls :: [ Either ObjectRelation ObjectPermission ]
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic)

-- * Printer

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
ppPermissionExpression (Ref tr)    = ppTypeReference tr
ppPermissionExpression (Union a b) = ppPermissionExpression a <+> PP.char '+' <+> ppPermissionExpression b

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

-- * Parser

type Parser = Parsec Void Text


sc :: Parser ()
sc = L.space
  hspace1
  (L.skipLineComment "//")
  (L.skipBlockComment "/*" "*/")

lexeme :: Parser a -> Parser a
lexeme = L.lexeme sc

symbol :: Text -> Parser Text
symbol = L.symbol sc

  -- fixme: how are characters escaped?
pName :: Parser Text
pName = T.pack <$> some alphaNumChar

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
  do a <- pTypeReference
     mop <- optional $ satisfy (\c -> c `elem` ("+&-" :: [Char]))
     case mop of
       Nothing -> pure (Ref a)
       (Just '+') ->
         do sc
            b <- pPermissionExpression
            pure $ Union (Ref a) b

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
     defs <- pDef `sepBy` eol
     rcurlyBrace
     pure (Definition n defs)

test_pDefinition :: IO ()
test_pDefinition =
  do parseTest pDefinition "definition user {}"
     parseTest pDefinition $ "definition user {relation writer: user\nrelation reader: user}"
     parseTest pDefinition $ "definition user {relation writer: user\nrelation reader: user\n permission edit = writer}"


