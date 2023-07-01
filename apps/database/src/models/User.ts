import type { RelationMappings } from "objection";

import { Model } from "../util/model.js";
import { mergeSchemas, timestampsSchema } from "../util/schemas.js";
import { Account } from "./Account.js";
import { Team } from "./Team.js";

export class User extends Model {
  static override tableName = "users";

  static override jsonSchema = mergeSchemas(timestampsSchema, {
    required: [],
    properties: {
      email: { type: ["string", "null"] },
      accessToken: { type: "string" },
    },
  });

  email!: string | null;
  accessToken!: string;

  static override get relationMappings(): RelationMappings {
    return {
      account: {
        relation: Model.BelongsToOneRelation,
        modelClass: Account,
        join: {
          from: "users.id",
          to: "accounts.userId",
        },
      },
      ownedTeams: {
        relation: Model.ManyToManyRelation,
        modelClass: Team,
        join: {
          from: "users.id",
          through: {
            from: "team_users.userId",
            to: "team_users.teamId",
          },
          to: "teams.id",
        },
        modify: (query) => query.where({ "team_users.userLevel": "owner" }),
      },
      teams: {
        relation: Model.ManyToManyRelation,
        modelClass: Team,
        join: {
          from: "users.id",
          through: {
            from: "team_users.userId",
            to: "team_users.teamId",
          },
          to: "teams.id",
        },
      },
    };
  }

  account?: Account;
  teams?: Team[];
  ownedTeams?: Team[];

  $checkWritePermission(user: User) {
    return User.checkWritePermission(this.id, user);
  }

  static checkWritePermission(userId: string, user: User) {
    if (!user) return false;
    return userId === user.id;
  }

  $checkReadPermission(user: User) {
    return User.checkReadPermission(this.id, user);
  }

  static checkReadPermission(userId: string, user: User) {
    if (!user) return false;
    return userId === user.id;
  }
}
