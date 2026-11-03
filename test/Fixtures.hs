{-# LANGUAGE QuasiQuotes #-}
-- | Fragments for the tests.  They are in their own module because a
-- 'schemaFragmentFile' splice can only use fragments from other modules.
module Fixtures (baseFragment) where

import AccessControl.SchemaFragment (SchemaFragment, schemaFragment)

-- | users and groups, which test/fixtures/page.schema refers to
baseFragment :: SchemaFragment
baseFragment =
  [schemaFragment|
    definition user {}

    /* a group of users, or of other groups */
    definition usergroup {
      relation direct_member: user | usergroup#member
      permission member = direct_member
    }
  |]
