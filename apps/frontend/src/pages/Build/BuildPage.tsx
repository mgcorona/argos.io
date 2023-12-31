import { useQuery } from "@apollo/client";
import { useEffect } from "react";

import { PaymentBanner } from "@/containers/PaymentBanner";
import { graphql } from "@/gql";

import { BuildHeader } from "./header/BuildHeader";
import { BuildHotkeysDialog } from "./BuildHotkeys";
import { BuildNotFound } from "./BuildNotFound";
import type { BuildParams } from "./BuildParams";
import { BuildWorkspace } from "./BuildWorkspace";
import { OvercapacityBanner } from "./OvercapacityBanner";
import { useBuildHotkeysDialogState } from "./BuildHotkeysDialogState";

const ProjectQuery = graphql(`
  query BuildPage_Project(
    $accountSlug: String!
    $projectName: String!
    $buildNumber: Int!
  ) {
    project(accountSlug: $accountSlug, projectName: $projectName) {
      id
      ...BuildHeader_Project
      ...BuildWorkspace_Project
      account {
        id
        ...OvercapacityBanner_Account
        ...PaymentBanner_Account
      }
      build(number: $buildNumber) {
        id
        status
        ...BuildHeader_Build
        ...BuildWorkspace_Build
      }
    }
  }
`);

export const BuildPage = ({ params }: { params: BuildParams }) => {
  const { data, error, refetch } = useQuery(ProjectQuery, {
    variables: {
      accountSlug: params.accountSlug,
      projectName: params.projectName,
      buildNumber: params.buildNumber,
    },
  });

  const project = data?.project ?? null;
  const build = project?.build ?? null;
  const buildStatusProgress = Boolean(
    build?.status &&
      (build.status === "pending" || build.status === "progress"),
  );
  const { hotkeysDialog } = useBuildHotkeysDialogState();

  useEffect(() => {
    if (buildStatusProgress) {
      const interval = setInterval(() => {
        refetch();
      }, 2000);

      return () => clearInterval(interval);
    }
    return undefined;
  }, [buildStatusProgress, refetch]);

  if (error) {
    throw error;
  }

  if (data && !data.project?.build) {
    return <BuildNotFound />;
  }

  return (
    <>
      {hotkeysDialog && <BuildHotkeysDialog dialog={hotkeysDialog} />}
      <div className="m flex h-screen min-h-0 flex-col">
        {data?.project?.account && (
          <>
            <PaymentBanner account={data.project.account} />
            <OvercapacityBanner
              account={data.project.account}
              accountSlug={params.accountSlug}
            />
          </>
        )}
        <BuildHeader
          buildNumber={params.buildNumber}
          accountSlug={params.accountSlug}
          projectName={params.projectName}
          build={build}
          project={data?.project ?? null}
        />
        {project && build ? (
          <BuildWorkspace params={params} build={build} project={project} />
        ) : null}
      </div>
    </>
  );
};
