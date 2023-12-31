/**
 * @param {import('knex').Knex} knex
 */
export const up = async (knex) => {
  await knex.schema
    .createTable("users", (table) => {
      table.bigIncrements("id").primary();
      table.integer("githubId").notNullable().index();
      table.string("name").notNullable();
      table.string("email").notNullable();
      table.dateTime("createdAt").notNullable();
      table.dateTime("updatedAt").notNullable();
    })
    .createTable("organizations", (table) => {
      table.bigIncrements("id").primary();
      table.integer("githubId").notNullable().index();
      table.string("name").notNullable();
      table.dateTime("createdAt").notNullable();
      table.dateTime("updatedAt").notNullable();
    })
    .createTable("repositories", (table) => {
      table.bigIncrements("id").primary();
      table.integer("githubId").notNullable().index();
      table.string("name").notNullable();
      table.boolean("enabled").notNullable().defaultTo(false).index();
      table.dateTime("createdAt").notNullable();
      table.dateTime("updatedAt").notNullable();
    })
    .createTable("screenshot_buckets", (table) => {
      table.bigIncrements("id").primary();
      table.string("name").notNullable().index();
      table.string("commit").notNullable().index();
      table.string("branch").notNullable();
      table.string("jobStatus").notNullable();
      table.dateTime("createdAt").notNullable();
      table.dateTime("updatedAt").notNullable();
    })
    .createTable("screenshots", (table) => {
      table.bigIncrements("id").primary();
      table
        .bigInteger("screenshotBucketId")
        .notNullable()
        .references("screenshot_buckets.id");
      table.string("name").notNullable().index();
      table.string("s3Id").notNullable().index();
      table.dateTime("createdAt").notNullable();
      table.dateTime("updatedAt").notNullable();
    })
    .createTable("builds", (table) => {
      table.bigIncrements("id").primary();
      table
        .bigInteger("baseScreenshotBucketId")
        .notNullable()
        .references("screenshot_buckets.id");
      table
        .bigInteger("compareScreenshotBucketId")
        .notNullable()
        .references("screenshot_buckets.id");
      table.dateTime("createdAt").notNullable();
      table.dateTime("updatedAt").notNullable();
    })
    .createTable("screenshot_diffs", (table) => {
      table.bigIncrements("id").primary();
      table.bigInteger("buildId").notNullable().references("builds.id");
      table
        .bigInteger("baseScreenshotId")
        .notNullable()
        .references("screenshots.id");
      table
        .bigInteger("compareScreenshotId")
        .notNullable()
        .references("screenshots.id");
      table.integer("score").notNullable();
      table.string("jobStatus").notNullable();
      table.string("validationStatus").notNullable();
      table.dateTime("createdAt").notNullable();
      table.dateTime("updatedAt").notNullable();
    });
};

/**
 * @param {import('knex').Knex} knex
 */
export const down = async (knex) => {
  await knex.schema
    .dropTableIfExists("screenshot_diffs")
    .dropTableIfExists("builds")
    .dropTableIfExists("screenshots")
    .dropTableIfExists("screenshot_buckets")
    .dropTableIfExists("repositories")
    .dropTableIfExists("organizations")
    .dropTableIfExists("users");
};
