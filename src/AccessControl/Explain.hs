-- | Views of an 'Explanation', the tree 'AccessControl.Check.check'
-- walks: what the check actually needed, and every way the subject is
-- allowed.
module AccessControl.Explain
  ( Explanation(..)
  , How(..)
  , ExprExplanation(..)
  , ExprHow(..)
  , RelationExplanation(..)
  , explain
  , explainIndexed
  , deciding
  , grantingPaths
  ) where

import AccessControl.Check
import AccessControl.Relation (RelationTuple)
import Data.List (nub)

-- | What 'check' evaluated to reach its answer, as it evaluates it: each
-- union stops at its first branch that allows, each relation at the
-- first tuple or subject set that names the subject, and each arrow at
-- the first subject on which the target holds.  The branches before that
-- one were evaluated and refused, and are kept in full; the ones after it
-- are left out ('ExNotEvaluated' for a branch of a union).
--
-- A refusal is unchanged: every branch had to be tried, and each is a
-- reason.
deciding :: Explanation -> Explanation
deciding e
  | not (exAllowed e) = e
  | otherwise =
      e { exHow = case exHow e of
                    ByPermission x -> ByPermission (decidingExpr x)
                    ByRelation r   -> ByRelation (decidingRelation r)
                    how            -> how }

decidingExpr :: ExprExplanation -> ExprExplanation
decidingExpr x
  | not (eeAllowed x) = x
  | otherwise =
      x { eeHow = case eeHow x of
                    ExUnion l r
                      | eeAllowed l -> ExUnion (decidingExpr l) (r { eeHow = ExNotEvaluated })
                      | otherwise   -> ExUnion l (decidingExpr r)
                    ExRelation r -> ExRelation (decidingRelation r)
                    ExName e     -> ExName (deciding e)
                    ExArrow fs   -> ExArrow (decidingFollowed fs)
                    how          -> how }

decidingRelation :: RelationExplanation -> RelationExplanation
decidingRelation r
  | not (reAllowed r) = r
  | (m : _) <- reMatches r = r { reMatches = [m], reSubjectSets = [], reOthers = [] }
  | otherwise = r { reSubjectSets = decidingFollowed (reSubjectSets r), reOthers = [] }

-- | Those refused before the first that allows, and that one.
decidingFollowed :: [ (RelationTuple, Explanation) ] -> [ (RelationTuple, Explanation) ]
decidingFollowed fs =
  case break (exAllowed . snd) fs of
    (refused, (rt, e) : _) -> refused ++ [(rt, deciding e)]
    (refused, [])          -> refused

-- | Every way the subject is allowed, each as the tuples followed from
-- the resource down to the one that names the subject: for instance a
-- subject set tuple and then the group's tuple naming the user, or an
-- arrow's tuple and then the tuple on its subject.  Empty if it is not
-- allowed.  This evaluates every branch.
grantingPaths :: Explanation -> [ [ RelationTuple ] ]
grantingPaths = nub . go
  where
    go e
      | not (exAllowed e) = []
      | otherwise =
          case exHow e of
            ByPermission x -> expr x
            ByRelation r   -> relation r
            _              -> []
    expr x
      | not (eeAllowed x) = []
      | otherwise =
          case eeHow x of
            ExUnion l r  -> expr l ++ expr r
            ExRelation r -> relation r
            ExName e     -> go e
            ExArrow fs   -> followed fs
            _            -> []
    relation r = [ [m] | m <- reMatches r ] ++ followed (reSubjectSets r)
    followed fs = [ rt : p | (rt, e) <- fs, p <- go e ]
