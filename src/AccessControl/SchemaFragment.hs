{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language DeriveLift #-}
{-# language OverloadedStrings #-}
{-# language TemplateHaskell #-}
-- | A schema can be put together from fragments, for instance one per
-- plugin, each kept in its own file.  A fragment is checked when the code
-- that contains it is compiled, against the fragments it depends on, and
-- keeps its original text so the schema that is stored still has its
-- comments.
module AccessControl.SchemaFragment
  ( SchemaFragment(..)
  , FragmentError(..)
  , ppFragmentError
  , checkFragment
  , schemaFragmentFile
  , schemaFragment
  , transitiveDepends
  , mergeFragments
  ) where

import AccessControl.Schema (Definition(..), Schema(..), SchemaError(..), parseSchema, ppSchemaError, validateSchema)
import qualified Data.ByteString as BS
import Data.Data (Data)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8)
import GHC.Generics (Generic)
import Language.Haskell.TH (Q, Exp, runIO)
import Language.Haskell.TH.Quote (QuasiQuoter(..))
import Language.Haskell.TH.Syntax (Lift, addDependentFile, lift)
import Text.PrettyPrint.HughesPJ (($+$))
import qualified Text.PrettyPrint.HughesPJ as PP

data SchemaFragment = SchemaFragment
  { fragmentText    :: Text             -- ^ the source, comments and layout included
  , fragmentSchema  :: Schema           -- ^ 'fragmentText' parsed
  , fragmentDepends :: [SchemaFragment] -- ^ the fragments whose definitions this one refers to
  }
  deriving (Eq, Ord, Read, Show, Data, Generic, Lift)

data FragmentError
  = FragmentParseError String
  | FragmentInconsistent [SchemaError] -- ^ problems in the fragment's own definitions
  deriving (Eq, Ord, Read, Show, Generic)

ppFragmentError :: FragmentError -> PP.Doc
ppFragmentError (FragmentParseError e) = PP.text "Schema fragment parse error" $+$ PP.nest 2 (PP.vcat (map PP.text (lines e)))
ppFragmentError (FragmentInconsistent errs) = PP.text "Schema fragment is not consistent." $+$ PP.nest 2 (PP.vcat (map ppSchemaError errs))

-- | the fragments these depend on, directly or not, and these themselves, each once
transitiveDepends :: [SchemaFragment] -> [SchemaFragment]
transitiveDepends = go []
  where
    go seen [] = reverse seen
    go seen (f : fs)
      | f `elem` seen = go seen fs
      | otherwise     = go (f : seen) (fragmentDepends f ++ fs)

-- | Parse a fragment and check it against the definitions of the fragments
-- it depends on.  Only problems in its own definitions are reported, the
-- others were checked when they were built.
checkFragment :: [SchemaFragment] -> Text -> Either FragmentError SchemaFragment
checkFragment deps txt =
  case parseSchema txt of
    (Left e) -> Left (FragmentParseError e)
    (Right sch) ->
      let own     = map defName (definitions sch)
          context = concatMap (definitions . fragmentSchema) (transitiveDepends deps)
          errs    = [ e | e <- validateSchema (Schema (context ++ definitions sch)), seDefinition e `elem` own ]
      in if null errs then Right (SchemaFragment txt sch deps) else Left (FragmentInconsistent errs)

-- | A fragment read from a file when the module that uses it is compiled,
-- and checked against @deps@, which must come from other modules:
--
-- > pageFragment :: SchemaFragment
-- > pageFragment = $(schemaFragmentFile [clckFragment] "page.schema")
--
-- The path is relative to the directory the compiler runs in, the package
-- root under cabal.  Editing the file recompiles the module.
schemaFragmentFile :: [SchemaFragment] -> FilePath -> Q Exp
schemaFragmentFile deps path =
  do addDependentFile path
     txt <- runIO (decodeUtf8 <$> BS.readFile path)
     case checkFragment deps txt of
       (Left err)   -> fail (path ++ ":\n" ++ show (ppFragmentError err))
       (Right frag) -> lift frag

-- | an inline fragment with no dependencies, checked at compile time
schemaFragment :: QuasiQuoter
schemaFragment = QuasiQuoter
  { quoteExp  = \s -> either (fail . show . ppFragmentError) lift (checkFragment [] (T.pack s))
  , quotePat  = error "schemaFragment does not define a pattern quoter"
  , quoteType = error "schemaFragment does not define a type quoter"
  , quoteDec  = error "schemaFragment does not define a declaration quoter"
  }

-- | Combine fragments into one schema: their texts one after another in
-- the order given, and the combined schema, if it is consistent.  The
-- fragments' own dependencies are not added, each must be in the list
-- itself, so a missing one shows up as an 'UnknownType'.
mergeFragments :: [SchemaFragment] -> Either [SchemaError] (Text, Schema)
mergeFragments frags =
  case validateSchema sch of
    []   -> Right (T.intercalate "\n\n" (map (T.strip . fragmentText) frags) <> "\n", sch)
    errs -> Left errs
  where
    sch = Schema (concatMap (definitions . fragmentSchema) frags)
