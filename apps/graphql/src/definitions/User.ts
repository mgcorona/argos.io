import gqlTag from "graphql-tag";

import { Account, Purchase, User } from "@argos-ci/database/models";
import { GhApiInstallation, getTokenOctokit } from "@argos-ci/github";

import type { IResolvers } from "../__generated__/resolver-types.js";
import { unauthenticated } from "../util.js";

// eslint-disable-next-line import/no-named-as-default-member
const { gql } = gqlTag;

export const typeDefs = gql`
  type User implements Node & Account {
    id: ID!
    stripeCustomerId: String
    stripeClientReferenceId: String!
    hasPaidPlan: Boolean!
    consumptionRatio: Float
    currentMonthUsedScreenshots: Int!
    screenshotsLimitPerMonth: Int
    slug: String!
    name: String
    plan: Plan
    periodStartDate: DateTime
    periodEndDate: DateTime
    purchase: Purchase
    purchaseStatus: PurchaseStatus
    oldPaidPurchase: Purchase
    permissions: [Permission!]!
    projects(after: Int!, first: Int!): ProjectConnection!
    ghAccount: GithubAccount
    avatar: AccountAvatar!
    lastPurchase: Purchase
    teams: [Team!]!
    ghInstallations: GhApiInstallationConnection!
    hasSubscribedToTrial: Boolean!
    trialStatus: TrialStatus
    hasForcedPlan: Boolean!
    pendingCancelAt: DateTime
    paymentProvider: PurchaseSource
    vercelConfiguration: VercelConfiguration
    gitlabAccessToken: String

    # User specific
    linkedToGithub: Boolean!
  }

  type UserConnection implements Connection {
    pageInfo: PageInfo!
    edges: [User!]!
  }

  extend type Query {
    "Get the authenticated user"
    me: User
  }
`;

export const resolvers: IResolvers = {
  Query: {
    me: async (_root, _args, ctx) => {
      return ctx.auth?.account || null;
    },
  },
  User: {
    linkedToGithub: async (account, _args, ctx) => {
      if (!account.userId) {
        throw new Error("Invariant: account.userId is undefined");
      }
      const user = await ctx.loaders.User.load(account.userId);
      return Boolean(user.accessToken);
    },
    hasSubscribedToTrial: async (account) => {
      return account.$checkHasSubscribedToTrial();
    },
    lastPurchase: async (account) => {
      if (!account.userId) {
        throw new Error("Invariant: account.userId is undefined");
      }
      const purchase = await Purchase.query()
        .findOne({ purchaserId: account.userId })
        .orderBy("updatedAt");
      return purchase ?? null;
    },
    teams: async (account) => {
      if (!account.userId) {
        throw new Error("Invariant: account.userId is undefined");
      }
      return Account.query()
        .orderBy([
          { column: "name", order: "asc" },
          { column: "slug", order: "asc" },
        ])
        .whereIn(
          "teamId",
          User.relatedQuery("teams").select("teams.id").for(account.userId),
        );
    },
    ghInstallations: async (account, _args, ctx) => {
      if (!ctx.auth) {
        throw unauthenticated();
      }
      if (account.id !== ctx.auth.account.id) {
        throw new Error(
          "Invariant: ghInstallations can only be accessed by the authenticated user",
        );
      }
      if (!ctx.auth.user.accessToken) {
        return { edges: [], pageInfo: { hasNextPage: false, totalCount: 0 } };
      }
      const octokit = getTokenOctokit(ctx.auth.user.accessToken);
      const apiInstallations =
        await octokit.apps.listInstallationsForAuthenticatedUser({
          per_page: 100,
        });
      return {
        edges: apiInstallations.data.installations as GhApiInstallation[],
        pageInfo: {
          hasNextPage: false,
          totalCount: apiInstallations.data.total_count,
        },
      };
    },
  },
};
