import gqlTag from "graphql-tag";

const { gql } = gqlTag;

export const typeDefs = gql`
  type Query {
    ping: Boolean!
  }

  type Mutation {
    ping: Boolean!
  }

  schema {
    query: Query
    mutation: Mutation
  }
`;

export const resolvers = {
  Query: {
    ping() {
      return true;
    },
  },
  Mutation: {
    ping() {
      return true;
    },
  },
};
