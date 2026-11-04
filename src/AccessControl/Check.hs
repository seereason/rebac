{-# language DataKinds #-}
{-# language DeriveDataTypeable #-}
{-# language DeriveGeneric #-}
{-# language OverloadedStrings #-}
{-# language QuasiQuotes #-}
{-# language MultiWayIf #-}
module AccessControl.Check where

import AccessControl.Relation
import AccessControl.Schema
import AccessControl.TupleIndex (TupleIndex, resourcesOfType, tuplesFor)
import AccessControl.Validate (RelPerm(..))
import Data.Time.Clock.POSIX (POSIXTime)
import           Data.Map (Map)
import qualified Data.Map as Map
import Data.Data (Data)
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (isNothing)
import Data.SafeCopy (SafeCopy)
import           Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics

data Access
  = Allowed
  | NotAllowed [Text]
  deriving (Eq, Ord, Read, Show, Data, Generic)

instance SafeCopy Access

instance Semigroup Access where
  Allowed <> _       = Allowed
  _       <> Allowed = Allowed
  (NotAllowed l) <> (NotAllowed r) = NotAllowed (l ++ r)

instance Monoid Access where
  mempty = NotAllowed []

isAllowed :: Access -> Bool
isAllowed Allowed = True
isAllowed _       = False

filterExpired :: Maybe POSIXTime -> [ RelationTuple ] -> [ RelationTuple ]
filterExpired mNow = filter (notExpired mNow)

{-
As an alternative implementation -- could we have a lazy function which expands the permission tree, and then a second function which just searches that tree.

The expansion function seems useful for diagnostic purposes.

If a RelationTuple has caveats such as an expiration then the relations it matches against in the schema must also have those caveats.

For example, if we have:

    relation reader: user

And a RelationTuple:


    document:somedocument#reader@user:sean[expiration:2022-12-31T23:59:59Z]


That RelationTuple will not match because it has an expiration date, but the relation only matches relation tuples that do not have an expiration. Instead we need the schema:

    relation reader: user | user with expiration

Now the relation can match with users that do or do not have an expiration time. If we have:

    relation reader: user with expiration

Then all reader relations must have an expiration to match.


-- FIXME:

The current implementation does not seem to validate against the schema (aka, rsDefMap). That is problematic for sure.

I think it means that you can insert arbitrary RelationTuples that grant a subject permission to a resource even if the schema does not actually allow it.

The schema is basically the type system.

This suggests that relation tuples can only be inserted if they match the schema, and also, the schema can only be modified in ways that do not cause any existing relation tuples to become invalid.

-}
check :: Map Text RelPerm
      -> [ RelationTuple ]
      -> Object NoWildcard  -- ^ resource
      -> Permission         -- ^ permission
      -> Object NoWildcard  -- ^ subject
      -> Maybe POSIXTime
      -> Access
check defMap tuples = checkOnPath Set.empty defMap (\res -> filter ((== res) . resource) tuples)

-- | 'check' with the tuples in a 'TupleIndex', which finds a resource's
-- tuples without looking at all of them.  Building an index costs several
-- list scans, so this pays off when the index is kept, for instance
-- alongside the tuples in the stored state, rather than built per check.
checkIndexed :: Map Text RelPerm
             -> TupleIndex
             -> Object NoWildcard  -- ^ resource
             -> Permission         -- ^ permission
             -> Object NoWildcard  -- ^ subject
             -> Maybe POSIXTime
             -> Access
checkIndexed defMap idx = checkOnPath Set.empty defMap (\res -> tuplesFor res idx)

-- | The resources of a type on which the subject has a permission (or
-- relation), in the index's order: SpiceDB's LookupResources, which answers
-- questions like "which reports can this user view".
--
-- This version checks each resource of the type that has tuples.  That is
-- correct by construction, since 'checkIndexed' never allows anything on a
-- resource with no tuples, but it costs a check per resource of the type.
lookupResources :: Map Text RelPerm
                -> TupleIndex
                -> ObjectType         -- ^ the type of resource to look for
                -> Permission         -- ^ permission
                -> Object NoWildcard  -- ^ subject
                -> Maybe POSIXTime
                -> [ Object NoWildcard ]
lookupResources defMap idx ty perm subject now =
  [ res | res <- resourcesOfType ty idx, isAllowed (checkIndexed defMap idx res perm subject now) ]

-- | 'check', carrying the @(resource, name)@ pairs being evaluated further
-- up the recursion; see 'explainOnPath'.  The answer is the verdict of the
-- explanation, which is only built as far as the verdict needs.
checkOnPath :: Set (Object NoWildcard, Text)
            -> Map Text RelPerm
            -> (Object NoWildcard -> [ RelationTuple ])  -- ^ tuplesOf
            -> Object NoWildcard  -- ^ resource
            -> Permission         -- ^ permission
            -> Object NoWildcard  -- ^ subject
            -> Maybe POSIXTime
            -> Access
checkOnPath path defMap tuplesOf resource perm subject now =
  toAccess (explainOnPath path defMap tuplesOf resource perm subject now)

-- | 'Allowed', or 'NotAllowed' with the reasons, from the explanation.
toAccess :: Explanation -> Access
toAccess e
  | exAllowed e = Allowed
  | otherwise   = NotAllowed (reasons e)

-- * Explanations

-- | How a name, a permission or a relation, was evaluated on a resource
-- for a subject: the tree 'check' walks.
--
-- It is built lazily, and 'check' reads only the verdicts ('exAllowed'),
-- which stop at the first branch that allows, as 'check' always has.  So
-- what a check does not need is never built.  Forcing the whole tree
-- evaluates every branch instead: every way the subject is allowed, or
-- every reason it is not.  "AccessControl.Explain" has views of it.
data Explanation = Explanation
  { exResource :: Object NoWildcard
  , exName     :: Text
  , exAllowed  :: Bool
  , exHow      :: How
  }
  deriving (Eq, Show, Generic)

instance SafeCopy Explanation

-- | How an 'Explanation' was decided.
data How
  = Cycle                         -- ^ this name on this resource is already being evaluated further up, so this branch is not allowed
  | NoTuples                      -- ^ the resource has no tuples at all
  | UndefinedType                 -- ^ the resource's type is not defined in the schema
  | UndefinedName                 -- ^ the name is neither a permission nor a relation of the resource's type
  | ByPermission ExprExplanation  -- ^ a permission, by its expression
  | ByRelation RelationExplanation  -- ^ a relation, by its tuples
  deriving (Eq, Show, Generic)

instance SafeCopy How

-- | How a permission expression, or part of one, was evaluated.
data ExprExplanation = ExprExplanation
  { eeExpr    :: PermissionExpression
  , eeAllowed :: Bool
  , eeHow     :: ExprHow
  }
  deriving (Eq, Show, Generic)

instance SafeCopy ExprExplanation

data ExprHow
  = ExUnion ExprExplanation ExprExplanation       -- ^ @a + b@
  | ExRelation RelationExplanation                -- ^ a relation of the same resource
  | ExName Explanation                            -- ^ another permission of the same resource, or a name that is neither
  | ExArrow [ (RelationTuple, Explanation) ]      -- ^ @rel->name@: each tuple of @rel@ followed, and @name@ on its subject
  | ExArrowFromNonRelation                        -- ^ @rel->name@ where @rel@ is not a relation
  | ExUnsupported                                 -- ^ @&@ or @-@, which 'check' does not implement
  | ExNotEvaluated                                -- ^ not needed for the answer; only 'AccessControl.Explain.deciding' leaves these
  deriving (Eq, Show, Generic)

instance SafeCopy ExprHow

-- | How a relation was evaluated: the subject has it if a tuple names it,
-- directly or by wildcard, or if it has the subject relation of a subject
-- set tuple.
data RelationExplanation = RelationExplanation
  { reRelation    :: Relation
  , reAllowed     :: Bool
  , reMatches     :: [ RelationTuple ]                  -- ^ tuples that name the subject, directly or by wildcard
  , reSubjectSets :: [ (RelationTuple, Explanation) ]   -- ^ subject set tuples, each with its subject relation evaluated on its object
  , reOthers      :: [ RelationTuple ]                  -- ^ tuples that name someone else
  , reExpired     :: [ RelationTuple ]                  -- ^ tuples ignored because they have expired
  }
  deriving (Eq, Show, Generic)

instance SafeCopy RelationExplanation

-- | Explain whether the subject has the permission (or relation) on the
-- resource; see 'Explanation'.
explain :: Map Text RelPerm
        -> [ RelationTuple ]
        -> Object NoWildcard  -- ^ resource
        -> Permission         -- ^ permission or relation
        -> Object NoWildcard  -- ^ subject
        -> Maybe POSIXTime
        -> Explanation
explain defMap tuples = explainOnPath Set.empty defMap (\res -> filter ((== res) . resource) tuples)

-- | 'explain' with the tuples in a 'TupleIndex'.
explainIndexed :: Map Text RelPerm
               -> TupleIndex
               -> Object NoWildcard  -- ^ resource
               -> Permission         -- ^ permission or relation
               -> Object NoWildcard  -- ^ subject
               -> Maybe POSIXTime
               -> Explanation
explainIndexed defMap idx = explainOnPath Set.empty defMap (\res -> tuplesFor res idx)

-- | 'explain', carrying the @(resource, name)@ pairs that are being
-- evaluated further up the recursion for this same subject.
--
-- Reaching one of those pairs again means a cycle in the tuples, such as two
-- groups that are members of each other.  Going round the cycle cannot find
-- anything the evaluation further up is not already looking for, so that
-- branch is not allowed ('Cycle').  Only the current path is kept, not
-- everything visited, so the same pair can still be reached by more than
-- one route.
--
-- @tuplesOf@ gives the tuples whose resource is the one given; 'explain'
-- and 'explainIndexed' differ only in how they find them.
explainOnPath :: Set (Object NoWildcard, Text)
              -> Map Text RelPerm
              -> (Object NoWildcard -> [ RelationTuple ])  -- ^ tuplesOf
              -> Object NoWildcard  -- ^ resource
              -> Permission         -- ^ permission or relation
              -> Object NoWildcard  -- ^ subject
              -> Maybe POSIXTime
              -> Explanation
explainOnPath path rsDefMap tuplesOf resource@(Object (ObjectType resourceTy) _) (Permission name) subject now
  | Set.member (resource, name) path = node False Cycle
  | otherwise =
  -- find the subset of RelationTuples which are relevant to the requested 'Resource'
  case tuplesOf resource of
    [] -> node False NoTuples
    relationTuples ->
      -- find the object definition that is relevant to the 'resourceType'
      case Map.lookup resourceTy rsDefMap of
           Nothing -> node False UndefinedType
           (Just (RelPerm rm pm)) ->
             -- separate filters rather than a partition: 'check' never reads
             -- the expired tuples, so they are never built
             let live    = filter (notExpired now) relationTuples
                 expired = filter (not . notExpired now) relationTuples in
             -- the name may be a permission or a relation, as it may in a
             -- subject set (@type#name@) or at the end of an arrow (@rel->name@)
             case Map.lookup name pm of
               (Just expr) -> let e = explainExpr live expired rm expr in node (eeAllowed e) (ByPermission e)
               Nothing
                 | Map.member name rm -> let r = explainRelation live expired (Relation name) in node (reAllowed r) (ByRelation r)
                 | otherwise -> node False UndefinedName
  where
    node allowed how = Explanation resource name allowed how

    -- the path for anything this evaluation recurses into
    path' = Set.insert (resource, name) path

    subjectIdMatch :: ObjectId -> WildcardObjectId -> Bool
    subjectIdMatch _ Wildcard = True
    subjectIdMatch (ObjectId a) (Specific (ObjectId b)) = a == b

    -- | does a tuple with no subject relation name this subject, directly or by wildcard?
    isDirectMatch :: RelationTuple -> Bool
    isDirectMatch (RelationTuple _ _ (Object subjectTypeB subjectIdB) _ _ _) =
      let Object subjectTypeA subjectIdA = subject
      in (subjectTypeA == subjectTypeB) && (subjectIdMatch subjectIdA subjectIdB)

    -- | Only the tuples of this relation count; a subject set on some other
    -- relation of the resource must not grant this one.  A tuple naming the
    -- subject decides it; otherwise each subject set in turn, e.g. for
    -- @page:1#viewer\@usergroup:x#member@, is the subject a member of
    -- @usergroup:x@?  A wildcard subject set, @type:*#rel@, is not valid
    -- and grants nothing.
    explainRelation :: [ RelationTuple ] -> [ RelationTuple ] -> Relation -> RelationExplanation
    explainRelation live expired wanted =
      let ofRel = filter ((== wanted) . relation) live
          direct  = filter (isNothing . subjectRelation) ofRel
          sets    = filter (not . isNothing . subjectRelation) ofRel
          matches = filter isDirectMatch direct
          others  = filter (not . isDirectMatch) direct
          followed = [ (rt, explainOnPath path' rsDefMap tuplesOf (Object ot oi) (Permission subRelation) subject now)
                     | rt@(RelationTuple _ _ (Object ot (Specific oi)) (Just (Relation subRelation)) _ _) <- sets ]
          wildcardSets = [ rt | rt@(RelationTuple _ _ (Object _ Wildcard) (Just _) _ _) <- sets ]
      in RelationExplanation
           { reRelation    = wanted
           , reAllowed     = not (null matches) || any (exAllowed . snd) followed
           , reMatches     = matches
           , reSubjectSets = followed
           , reOthers      = others ++ wildcardSets
           , reExpired     = filter ((== wanted) . relation) expired
           }

    explainExpr :: [ RelationTuple ]
                -> [ RelationTuple ]
                -> Map Text (NonEmpty TypeReference)
                -> PermissionExpression
                -> ExprExplanation
    explainExpr live expired rm expr =
      case expr of
        Union l r ->
          let l' = explainExpr live expired rm l
              r' = explainExpr live expired rm r
          in ExprExplanation expr (eeAllowed l' || eeAllowed r') (ExUnion l' r')
        Rel (Relation n) ->
          case Map.lookup n rm of
            -- not a relation, so it should be another permission of this
            -- resource; explainOnPath evaluates it, or reports that it is neither
            Nothing -> let e = explainOnPath path' rsDefMap tuplesOf resource (Permission n) subject now
                       in ExprExplanation expr (exAllowed e) (ExName e)
            Just _  -> let r = explainRelation live expired (Relation n)
                       in ExprExplanation expr (reAllowed r) (ExRelation r)
        -- @rel->name@: check @name@ on each subject of @rel@, of any of the
        -- plain types @rel@ allows.  Wildcard and subject set tuples are not
        -- followed; 'validateSchema' rejects arrows over relations that allow them.
        Arrow (Relation arrowRel) target ->
          case Map.lookup arrowRel rm of
            Nothing -> ExprExplanation expr False ExArrowFromNonRelation
            Just subjectTypes ->
              let types = [ ObjectType (referenceType st) | st <- NonEmpty.toList subjectTypes, referenceKind st == Plain ]
                  followed = [ (rt, explainOnPath path' rsDefMap tuplesOf subj (Permission target) subject now)
                             | (rt, subj) <- nubOn snd [ (rt, Object ty oi)
                                                       | rt@(RelationTuple _ r (Object ty (Specific oi)) Nothing _ _) <- live
                                                       , r == Relation arrowRel
                                                       , ty `elem` types ] ]
              in ExprExplanation expr (any (exAllowed . snd) followed) (ExArrow followed)
        -- '&' and '-'; 'validateSchema' rejects them
        _ -> ExprExplanation expr False ExUnsupported

    -- the first of each, in order
    nubOn f = go []
      where go _ [] = []
            go seen (x : xs) | f x `elem` seen = go seen xs
                             | otherwise       = x : go (f x : seen) xs

-- | Is the tuple in force at this time?  A tuple with an expiration is not
-- in force when no time is given.
notExpired :: Maybe POSIXTime -> RelationTuple -> Bool
notExpired mNow rt =
  case expiration rt of
    Nothing -> True
    (Just expires) ->
      case mNow of
        Nothing    -> False
        (Just now) -> expires > (posixTimeToExpiration now)

-- | Why an explanation is not allowed, one line for each way it was tried:
-- what 'NotAllowed' carries.
reasons :: Explanation -> [ Text ]
reasons (Explanation res name _ how) =
  case how of
    Cycle            -> [ name <> " on " <> obj res <> " is already being checked (a cycle)" ]
    NoTuples         -> [ "no tuples for " <> obj res ]
    UndefinedType    -> [ "type " <> unObjectType (objectType res) <> " is not defined" ]
    UndefinedName    -> [ name <> " is neither a permission nor a relation of " <> unObjectType (objectType res) ]
    ByPermission e   -> exprReasons e
    ByRelation r     -> relationReasons r
  where
    exprReasons e
      | eeAllowed e = []
      | otherwise =
          case eeHow e of
            ExUnion l r            -> exprReasons l ++ exprReasons r
            ExRelation r           -> relationReasons r
            ExName e'              -> reasons e'
            ExArrow []             -> [ "no subject to follow for " <> ppExpr (eeExpr e) <> " on " <> obj res ]
            ExArrow fs             -> concatMap (reasons . snd) fs
            ExArrowFromNonRelation -> [ ppExpr (eeExpr e) <> " on " <> obj res <> " does not start from a relation" ]
            ExUnsupported          -> [ ppExpr (eeExpr e) <> " is not supported" ]
            ExNotEvaluated         -> []
    relationReasons r
      | reAllowed r = []
      | otherwise =
          ("no " <> obj res <> "#" <> unRelation (reRelation r) <> " tuple names the subject") :
          concatMap (reasons . snd) (reSubjectSets r)
    obj = T.pack . show . ppObject
    ppExpr = T.pack . show . ppPermissionExpression
