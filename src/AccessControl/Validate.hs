{-# language DeriveDataTypeable #-}
{-# language DataKinds #-}
{-# language DeriveGeneric #-}
{-# language FlexibleInstances #-}
{-# language MultiParamTypeClasses #-}
{-# language MultiWayIf #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes, TemplateHaskell, DeriveLift #-}
{-# language StandaloneDeriving #-}
module AccessControl.Validate where

import AccessControl.Relation (Object(..), ObjectType(..), WildcardObjectId(..), Relation(..), RelationTuple(..), Tag(..), ppRelationTuple, ppText, rel, rels)
import AccessControl.Schema (Definition(..), ObjectPermission(..), ObjectRelation(..), Permission(..), PermissionExpression(..), ReferenceKind(..), Schema(..), TypeReference(..), ppPermissionExpression, ppTypeReference, ppTypeReferences, schema)
import Data.Data (Data)
import Debug.Trace (trace)
import Data.Either (partitionEithers)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import           Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (isJust, isNothing)
import Data.Text (Text)
import qualified Data.Text as Text
import GHC.Generics
import Text.PrettyPrint.HughesPJ (Doc, (<+>), ($$), ($+$))
import qualified Text.PrettyPrint.HughesPJ as PP

debugTrace = trace

mkDefMap
  :: [Definition]
  -> Map Text RelPerm
mkDefMap defs = Map.fromList $ map mkDefMapItem defs
 where
   mkDefMapItem (Definition nm decls) =
      let (rels, perms) = partitionEithers decls
          relMap  = Map.fromList $ map (\(ObjectRelation nm ot)   -> (nm, ot)) rels
          permMap = Map.fromList $ map (\(ObjectPermission nm ex) -> (nm, ex)) perms
      in (nm, RelPerm relMap permMap)

data RelPerm = RelPerm
  { relMap  :: Map Text (NonEmpty TypeReference)
  , permMap :: Map Text PermissionExpression
  }
  deriving (Eq, Ord, Read, Show, Data, Generic)

ppRelMap :: Map Text (NonEmpty TypeReference) -> Doc
ppRelMap m =
  PP.vcat $ map ppRel (Map.toList m)
  where
    ppRel (nm,r) = PP.text "relation" <+> (ppText nm <> PP.char ':') <+> ppTypeReferences r

ppPermMap :: Map Text PermissionExpression -> Doc
ppPermMap m =
  PP.vcat $ map ppPerm (Map.toList m)
  where
    ppPerm (nm, p) = PP.text "permission" <+> ppText nm <+> PP.char '=' <+> ppPermissionExpression p

ppRelPerm :: RelPerm -> Doc
ppRelPerm (RelPerm r p) =
  ppRelMap r $+$ ppPermMap p

data Valid
  = Valid
  | NotValid [Text]
  deriving (Eq, Ord, Read, Show, Data)

isValid :: Valid -> Bool
isValid Valid = True
isValid _     = False

validate :: Schema -> RelationTuple -> Valid
validate (Schema defs) rt@(RelationTuple res@(Object (ObjectType resourceTy) _resourceId) (Relation rel) sub@(Object (ObjectType subjectType) subjectId) subRel mTag mExpiration) =
  let defMap = mkDefMap defs
  in case Map.lookup resourceTy defMap of
       Nothing -> NotValid ["resource has unknown object type " <> resourceTy]
       (Just (RelPerm rm pm)) ->
         case Map.lookup rel rm of
           Nothing -> NotValid ["relation " <> rel <> " not defined for " <> resourceTy]
           (Just typeReferences) ->
             anyValid $ map isMatch (NonEmpty.toList typeReferences)
  where
    anyValid :: [Valid] -> Valid
    anyValid attempts | any (\v -> v == Valid) attempts = Valid
    anyValid attempts = NotValid (concat [ reason | NotValid reason <- attempts ])

    expirationMatch tr refExp =
      if | (isNothing mExpiration) ->
             if | not refExp -> Valid
                | otherwise  -> NotValid [ "relation tuple does not have an expiration but one is required. " <> Text.pack (show $ (PP.text "type reference =") <+> ppTypeReference tr <+> (PP.text ", relation tuple =") <+> ppRelationTuple rt)]
         | otherwise ->
             if | refExp    -> Valid
                | otherwise -> NotValid [ "relation tuple has an expiration, but one is not allowed. " <> Text.pack (show $ (PP.text "type reference =") <+> ppTypeReference tr <+> (PP.text ", relation tuple =") <+> ppRelationTuple rt)]

    isMatch tr@(TypeReference refType refKind refExp) =
      if | (subjectType == refType) ->
             let expireValid = expirationMatch tr refExp
             in if | isValid expireValid ->
                       case refKind of
                         Plain -> case subjectId of
                                    Specific _ -> Valid
                                    Wildcard -> NotValid ["relation tuple has a wildcard, but wildcards are not allowed. " <> Text.pack (show $ (PP.text "type reference =") <+> ppTypeReference tr <+> (PP.text ", relation tuple =") <+> ppRelationTuple rt)]
                         SubjectWildcard ->
                           case subjectId of
                             Wildcard   -> Valid
                             Specific _ -> NotValid ["relation tuple has a specific id, but only wildcards are allowed. " <> Text.pack (show $ (PP.text "type reference =") <+> ppTypeReference tr <+> (PP.text ", relation tuple =") <+> ppRelationTuple rt)]
                   | otherwise -> expireValid
         | otherwise -> NotValid [ resourceTy <> " does not match " <> refType ]


schema1 :: Schema
schema1 =
  [schema|
    definition user {}

    definition organization {
        relation admin: user

        permission can_admin = admin
    }

    definition document {
        relation org: organization

        relation owner: user
        relation reader: user | user:* | user with expiration

        permission edit = owner
        permission view = reader + owner + org->can_admin

    }
  |]

rels1 :: [RelationTuple]
rels1 =
  [rels|
    pencil:somedocument#reader@user:sean                   # Sean is a reader on pencil:somedocument -- which is not a valid resource
    document:somedocument#eater@user:sean                  # Sean is a eater on somedocument        -- which is not a valid relation
    document:somedocument#reader@user:sean                 # Sean is a reader on somedocument
    document:somedocument#reader@user:fred                 # Fred is a reader on somedocument
    document:somedocument#owner@user:jill                  # Jill is the owner of somedocument
    organization:theorg#admin@user:hannah                  # Hannah is the admin of the organization
    document:somedocument#org@organization:theorg          # `theorg` is the organization for the document
    document:publicdoc#reader@user:*                       # a publicly readable document
    document:somedocument#reader@user:tom[expiration:2040-12-31T23:59:59Z] # Tom is a reader on somedocument, but only until 2040
  |]

rel1 = [rel|document:somedocument#reader@user:sean|]
