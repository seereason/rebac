{-# language DeriveDataTypeable #-}
{-# language DataKinds #-}
{-# language DeriveGeneric #-}
{-# language FlexibleInstances #-}
{-# language MultiParamTypeClasses #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes, TemplateHaskell, DeriveLift #-}
{-# language StandaloneDeriving #-}
module AccessControl.Schema where

import AccessControl.Relation (Object(..), ObjectWildcard(..), ObjectType(..), Relation(..), ToObject(..), pName, pRelation, ppRelation, ppText, sc, scnl)
import Data.Data (Data)
import Data.Either (lefts, rights)
import Data.SafeCopy (SafeCopy)
import Data.List (find, intercalate, intersperse, nub)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.Maybe (catMaybes, isJust)
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
import Text.Megaparsec.Error
import Text.PrettyPrint.HughesPJ ((<+>), ($$), ($+$))
import qualified Text.PrettyPrint.HughesPJ as PP
import qualified Text.Megaparsec.Char.Lexer as L -- (1)


-- * Common Expression Language

-- * Permission

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

class (ToObject resource, ToPermission permission, ToObject subject) => KnownPermission resource permission subject
-- instance KnownPermission (Object ResourceK) Permission (Object SubjectK)

instance KnownPermission (Object NoWildcard) Permission UserId
instance KnownPermission (Object NoWildcard) Permission (Maybe UserId)

data Comment
  = SingleLineComment Text
  | MultiLineComment [ Text ]
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

data ObjectRelation = ObjectRelation
  { orName :: Text
  , orObjectTypes :: NonEmpty TypeReference
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ObjectRelation
{-
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
-}

data ReferenceKind
  = Plain
  | SubjectWildcard
  | SubjectRelation Text
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy ReferenceKind

data TypeReference = TypeReference
  { referenceType       :: Text
  , referenceKind       :: ReferenceKind
  , referenceExpiration :: Bool            -- does this TypeReference have `with expiration` -- this  does not seem future proof for when we have CELs that could include the expiration
--  , objectRelation :: Maybe Text
  }
  deriving (Eq, Ord, Read, Show, Data, Typeable, Generic, Lift)

instance SafeCopy TypeReference

data PermissionExpression
  = Union        PermissionExpression PermissionExpression
  | Intersection PermissionExpression PermissionExpression
  | Exclusion    PermissionExpression PermissionExpression
  | Arrow        Relation Text
  | Rel          Relation
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
knownObjectTypes (Schema defs) = nub $ map (ObjectType . defName) defs

knownRelations :: Schema -> [ Relation ]
knownRelations (Schema defs) = nub $ concatMap (map rel . objectRelations) defs
  where
    rel :: ObjectRelation -> Relation
    rel or = Relation (orName or)
{-
knownSubjectRelations :: Schema -> [ Relation ]
knownSubjectRelations (Schema defs) = nub $ concatMap (map rel . objectRelations) defs
  where
    rel :: ObjectRelation -> Relation
    rel or = Relation (orObjectTypes or)
-}
-- * Predicates

knownObjectType :: Schema -> ObjectType -> Bool
knownObjectType (Schema defs) (ObjectType ot) =
  isJust $ find (\d -> defName d == ot) defs

-- * Printers
{-
ppResource :: Resource -> PP.Doc
ppResource (Resource n mId) =
  PP.text (T.unpack n) <> (case mId of
                             Nothing -> PP.empty
                             (Just (ResourceId i)) -> PP.char ':' <> PP.text (T.unpack i))
-}

ppReferenceKind :: ReferenceKind -> PP.Doc
ppReferenceKind Plain           = PP.empty
ppReferenceKind SubjectWildcard = PP.text ":*"
ppReferenceKind (SubjectRelation rel) = PP.char '#' <> ppText rel

ppTypeReference :: TypeReference -> PP.Doc
ppTypeReference (TypeReference r rKind expiration) =
  ppText r <> ppReferenceKind rKind <> ppExpiration expiration

ppExpiration :: Bool -> PP.Doc
ppExpiration False = PP.empty
ppExpiration True  = PP.text " with expiration"

ppPermissionExpression :: PermissionExpression -> PP.Doc
ppPermissionExpression (Union a b)        = ppPermissionExpression a <+> PP.char '+' <+> ppPermissionExpression b
ppPermissionExpression (Intersection a b) = ppPermissionExpression a <+> PP.char '&' <+> ppPermissionExpression b
ppPermissionExpression (Exclusion a b)    = ppPermissionExpression a <+> PP.char '-' <+> ppPermissionExpression b
ppPermissionExpression (Arrow rel pr)     = ppRelation rel <> PP.text "->" <> ppText pr
ppPermissionExpression (Rel rel)          = ppRelation rel

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

lexeme :: Parser a -> Parser a
lexeme = L.lexeme sc

symbol :: Text -> Parser Text
symbol = L.symbol sc


lcurlyBrace :: Parser Char
lcurlyBrace = char '{'

rcurlyBrace :: Parser Char
rcurlyBrace = char '}'

{-
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
-}

pReferenceKind :: Parser ReferenceKind
pReferenceKind =
  do char '#'
     t <- lexeme pName
     sc
     pure (SubjectRelation t)
  <|>
  do string ":*"
     sc
     pure SubjectWildcard
  <|>
   do sc
      pure Plain

pExpiration :: Parser Bool
pExpiration =
  do sc
     (string "with expiration" *> pure True) <|> pure False

pTypeReference :: Parser TypeReference
pTypeReference =
  do r <- pName
     k <- pReferenceKind
     e <- pExpiration
     pure (TypeReference r k e)

test_pTypeReference :: IO ()
test_pTypeReference =
  do parseTest pTypeReference "foo"
     parseTest pTypeReference "foo:*"
     parseTest pTypeReference "foo#rel"

{-
  do parseTest pTypeReference "foo"
     parseTest pTypeReference "foo:fooid"
     parseTest pTypeReference "foo:fooid#rel"
     parseTest pTypeReference "foo:*#rel"
     parseTest pTypeReference "foo#rel"
-}

pTypeReferences :: Parser (NonEmpty TypeReference)
pTypeReferences =
  do NonEmpty.fromList <$> (pTypeReference `sepBy` (lexeme $ char '|'))

test_pTypeReferences :: IO ()
test_pTypeReferences =
  do parseTest pTypeReferences "foo"
     parseTest pTypeReferences "foo#rel | moo | baz#rel | bar:* | baz"

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
  do parseTest pObjectRelation "relation writer: user | user:* | usergroup#member"


pArrowExpression :: Parser PermissionExpression
pArrowExpression =
  do rel <- pRelation
     string "->"
     pr  <- pName
     pure (Arrow rel pr)

test_pArrowExpression :: IO ()
test_pArrowExpression =
  do parseTest pArrowExpression "foo->bar"

pBaseExpression :: Parser PermissionExpression
pBaseExpression =
  (parens $
    do sc
       pPermissionExpression)
  <|>
    do Rel <$> lexeme pRelation
    where
      parens = between (symbol "(") (symbol ")")

-- FIXME: it is not clear that operator precedence is correct for things like:
-- @foo - bar & baz@
-- should that be @(foo - bar) & baz@ or @foo- (bar & baz)@
pPermissionExpression :: Parser PermissionExpression
pPermissionExpression =
  do a <- (try pArrowExpression) <|> pBaseExpression
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


-- fixme: add support for parens
{-
pPermissionExpression :: Parser PermissionExpression
pPermissionExpression =
  do let pArrow = try $
           do rel <- pRelation
              string "->"
              pr <- pName
              pure (Arrow rel pr)
     a <- pArrow <|> (Rel <$> pRelation)
     sc
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
-}
test_pPermissionExpression =
  do parseTest pPermissionExpression "writer"
     parseTest pPermissionExpression "(writer)"
     parseTest pPermissionExpression "writer + reader"
     parseTest pPermissionExpression "writer + (reader + commenter)"
     parseTest pPermissionExpression "(writer - reader) + commenter)"
     parseTest pPermissionExpression "writer - reader + commenter" -- fixme: is this actually parsed correctly?


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
     eof
     pure $ Schema defs

test_pSchema :: IO ()
test_pSchema =
  do let res = runParser pSchema "" (T.unlines [ "\ndefinition user {}"
                                               , "definition document {relation writer: user\nrelation reader: user | user:* | usergroup#member | user with expiration\n}"
                                               , "definition thing {relation writer: user\nrelation reader: user\n permission edit = writer\n permission view = writer + reader & some->arrow}\n\n"
                                               ])
     case res of
       (Right s) -> print $ ppSchema s
       (Left e) -> putStrLn $ errorBundlePretty e

parseSchema :: Text -> Either String Schema
parseSchema t =
  case runParser pSchema "" t of
    (Right s) -> Right s
    (Left e)  -> Left (errorBundlePretty e)

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


-- * Schema consistency

-- | a problem found by 'validateSchema'
data SchemaError = SchemaError
  { seDefinition :: Text       -- ^ the definition the problem is in
  , seMember     :: Maybe Text -- ^ the relation or permission the problem is in, if any
  , seProblem    :: SchemaProblem
  }
  deriving (Eq, Ord, Read, Show, Data, Generic)

instance SafeCopy SchemaError

-- | The @Unsupported...@ problems are valid in the schema language, but
-- 'AccessControl.Check.check' does not implement them, so a schema using them
-- would quietly never grant access (or, for @&@ and @-@, crash the check).
-- Remove them as 'AccessControl.Check.check' learns to handle each case.
data SchemaProblem
  = DuplicateDefinition                       -- ^ the definition name is used more than once
  | DuplicateMember                           -- ^ the relation or permission name is declared more than once in its definition
  | UnknownType Text                          -- ^ a type reference names a definition that does not exist
  | UnknownSubjectRelation Text Text          -- ^ @type#name@ where @type@ has no relation or permission @name@
  | UnknownName Text                          -- ^ a permission expression names something its definition does not declare
  | ArrowFromPermission Text                  -- ^ the left side of an arrow is a permission, it must be a relation
  | ArrowFromWildcard Text                    -- ^ the left side of an arrow is a relation that allows wildcard subjects
  | ArrowTargetMissing Text Text Text         -- ^ @rel->name@ where type @t@, which @rel@ refers to, has no @name@
  | PermissionCycle [Text]                    -- ^ permissions that only lead into a cycle among themselves, so they can never be granted
  | UnsupportedOperator Text                  -- ^ @&@ or @-@
  | UnsupportedArrowRelation Text             -- ^ an arrow over a relation that allows a subject set (@type#rel@), which 'AccessControl.Check.check' does not follow
  deriving (Eq, Ord, Read, Show, Data, Generic)

instance SafeCopy SchemaProblem

ppSchemaError :: SchemaError -> PP.Doc
ppSchemaError (SchemaError d mMember problem) =
  PP.text "definition" <+> (ppText d <> maybe PP.empty (\m -> PP.text "," <+> ppText m) mMember <> PP.char ':') <+> PP.text (problemText problem)
  where
    s = T.unpack
    problemText DuplicateDefinition = "is defined more than once"
    problemText DuplicateMember = "is declared more than once"
    problemText (UnknownType t) = "refers to type " ++ s t ++ ", which is not defined"
    problemText (UnknownSubjectRelation t n) = "refers to " ++ s t ++ "#" ++ s n ++ ", but " ++ s t ++ " has no relation or permission " ++ s n
    problemText (UnknownName n) = "refers to " ++ s n ++ ", which is not a relation or permission of " ++ s d
    problemText (ArrowFromPermission n) = "uses " ++ s n ++ "-> but " ++ s n ++ " is a permission, an arrow must start from a relation"
    problemText (ArrowFromWildcard n) = "uses " ++ s n ++ "-> but " ++ s n ++ " allows wildcard subjects"
    problemText (ArrowTargetMissing n t p) = "uses " ++ s n ++ "->" ++ s p ++ ", but " ++ s t ++ " has no " ++ s p
    problemText (PermissionCycle ps) = "has permissions that only lead into a cycle, never to a relation or an arrow: " ++ intercalate ", " (map s ps)
    problemText (UnsupportedOperator op) = "uses " ++ s op ++ ", which AccessControl.Check does not implement"
    problemText (UnsupportedArrowRelation n) = "uses " ++ s n ++ "->, but " ++ s n ++ " allows a subject set, which AccessControl.Check does not follow through an arrow"

-- | check that a schema is consistent with itself
--
-- Every name it uses must be defined, and it must only use what
-- 'AccessControl.Check.check' implements. An empty list means no problems.
validateSchema :: Schema -> [ SchemaError ]
validateSchema (Schema defs) =
  nub $ [ SchemaError n Nothing DuplicateDefinition | n <- duplicates (map defName defs) ] ++
        concatMap checkDefinition defs
  where
    -- the first definition wins, any others are reported as duplicates
    defMap :: Map.Map Text Definition
    defMap = Map.fromListWith (\_new old -> old) [ (defName d, d) | d <- defs ]

    declName :: Either ObjectRelation ObjectPermission -> Text
    declName = either orName opName

    lookupMember :: Text -> Text -> Maybe (Either ObjectRelation ObjectPermission)
    lookupMember ty n = Map.lookup ty defMap >>= find ((== n) . declName) . defDecls

    duplicates :: [Text] -> [Text]
    duplicates xs = [ x | (x, c) <- Map.toList (Map.fromListWith (+) [ (x, 1 :: Int) | x <- xs ]), c > 1 ]

    checkDefinition :: Definition -> [ SchemaError ]
    checkDefinition (Definition dn decls) =
      [ SchemaError dn (Just n) DuplicateMember | n <- duplicates (map declName decls) ] ++
      concat [ map (SchemaError dn (Just (orName r))) (concatMap checkReference (NonEmpty.toList (orObjectTypes r))) | Left r <- decls ] ++
      concat [ map (SchemaError dn (Just (opName p))) (checkExpression dn (opExpr p)) | Right p <- decls ] ++
      [ SchemaError dn Nothing (PermissionCycle ps) | let ps = ungroundedPermissions decls, not (null ps) ]

    -- | The permissions that can never be granted because every name they
    -- use leads only to other such permissions, so they all end up in a
    -- cycle.  These are the schemas SpiceDB rejects with "there exists a
    -- cycle in permissions", and like SpiceDB this lists all of them in one
    -- error, including those that only lead into a cycle.
    --
    -- A permission is grounded if its expression names a relation, uses an
    -- arrow, or names a grounded permission, whatever the operator, as in
    -- SpiceDB.  A cycle with a grounded member is fine, it is how recursive
    -- permissions are written.
    ungroundedPermissions :: [Either ObjectRelation ObjectPermission] -> [Text]
    ungroundedPermissions decls = Map.keys ungrounded
      where
        perms = Map.fromListWith (\_new old -> old) [ (opName p, opExpr p) | Right p <- decls ]
        relations = Set.fromList [ orName r | Left r <- decls ]
        -- a relation leads out, and is what 'AccessControl.Check.check' looks
        -- up first if a permission has the same name (a 'DuplicateMember');
        -- a name that is neither is reported as 'UnknownName', so let it pass
        leadsOut grounded n = Set.member n relations || not (Map.member n perms) || Set.member n grounded
        isGrounded grounded expr =
          case expr of
            Union a b        -> isGrounded grounded a || isGrounded grounded b
            Intersection a b -> isGrounded grounded a || isGrounded grounded b
            Exclusion a b    -> isGrounded grounded a || isGrounded grounded b
            Arrow _ _        -> True
            Rel (Relation n) -> leadsOut grounded n
        grow grounded =
          let grounded' = Set.fromList [ p | (p, e) <- Map.toList perms, isGrounded grounded e ]
          in if grounded' == grounded then grounded else grow grounded'
        ungrounded = Map.withoutKeys perms (Set.union relations (grow Set.empty))

    checkReference :: TypeReference -> [ SchemaProblem ]
    checkReference (TypeReference ty kind _)
      | not (Map.member ty defMap) = [ UnknownType ty ]
      | SubjectRelation n <- kind =
          case lookupMember ty n of
            Nothing -> [ UnknownSubjectRelation ty n ]
            Just _  -> []
      | otherwise = []

    checkExpression :: Text -> PermissionExpression -> [ SchemaProblem ]
    checkExpression dn expr =
      case expr of
        Union a b        -> checkExpression dn a ++ checkExpression dn b
        Intersection a b -> UnsupportedOperator "&" : checkExpression dn a ++ checkExpression dn b
        Exclusion a b    -> UnsupportedOperator "-" : checkExpression dn a ++ checkExpression dn b
        Rel (Relation n) ->
          case lookupMember dn n of
            Nothing -> [ UnknownName n ]
            Just _  -> []
        Arrow (Relation n) target ->
          case lookupMember dn n of
            Nothing        -> [ UnknownName n ]
            Just (Right _) -> [ ArrowFromPermission n ]
            Just (Left (ObjectRelation _ refs))
              | any ((== SubjectWildcard) . referenceKind) refs -> [ ArrowFromWildcard n ]
              | any ((/= Plain) . referenceKind) refs -> [ UnsupportedArrowRelation n ]
              -- every type the relation allows must have the target
              | otherwise -> concat [ checkArrowTarget n ty target | ty <- nub (map referenceType (NonEmpty.toList refs)) ]

    -- an undefined @ty@ has already been reported as 'UnknownType' on the relation
    checkArrowTarget :: Text -> Text -> Text -> [ SchemaProblem ]
    checkArrowTarget n ty target
      | not (Map.member ty defMap) = []
      | otherwise =
          case lookupMember ty target of
            Nothing -> [ ArrowTargetMissing n ty target ]
            Just _  -> []
