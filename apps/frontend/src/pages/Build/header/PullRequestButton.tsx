import { Link } from "react-router-dom";

import { Tooltip } from "@/ui/Tooltip";
import { Button, ButtonIcon } from "@/ui/Button";
import {
  GitMergeIcon,
  GitPullRequestClosedIcon,
  GitPullRequestDraftIcon,
  GitPullRequestIcon,
} from "@primer/octicons-react";
import { FragmentType, graphql, useFragment } from "@/gql";
import { PullRequestState } from "@/gql/graphql";

const PullRequestStatusIconFragment = graphql(`
  fragment PullRequestStatusIcon_PullRequest on PullRequest {
    draft
    merged
    state
  }
`);

const PullRequestStatusIcon = (props: {
  pullRequest: FragmentType<typeof PullRequestStatusIconFragment>;
}) => {
  const pullRequest = useFragment(
    PullRequestStatusIconFragment,
    props.pullRequest,
  );
  if (pullRequest.merged) {
    return (
      <ButtonIcon className="text-primary-low">
        <GitMergeIcon />
      </ButtonIcon>
    );
  }
  if (pullRequest.draft) {
    return (
      <ButtonIcon className="text-secondary-low">
        <GitPullRequestDraftIcon />
      </ButtonIcon>
    );
  }
  switch (pullRequest.state) {
    case PullRequestState.Closed: {
      return (
        <ButtonIcon className="text-danger-low">
          <GitPullRequestClosedIcon />
        </ButtonIcon>
      );
    }
    case PullRequestState.Open:
    default:
      return (
        <ButtonIcon className="text-success-low">
          <GitPullRequestIcon />
        </ButtonIcon>
      );
  }
};

const PullRequestButtonFragment = graphql(`
  fragment PullRequestButton_PullRequest on PullRequest {
    title
    number
    url
    ...PullRequestStatusIcon_PullRequest
  }
`);

export const PullRequestButton = (props: {
  pullRequest: FragmentType<typeof PullRequestButtonFragment>;
}) => {
  const pullRequest = useFragment(PullRequestButtonFragment, props.pullRequest);
  return (
    <Tooltip content="View pull request on GitHub">
      <Button
        color="neutral"
        variant="outline"
        size="small"
        className="min-w-0"
      >
        {(buttonProps) => (
          <Link {...buttonProps} to={pullRequest.url}>
            <PullRequestStatusIcon pullRequest={pullRequest} />
            {pullRequest.title ? (
              <span className="flex gap-2 min-w-0 max-w-prose items-center">
                <span className="flex-1 min-w-0 truncate">
                  {pullRequest.title}
                </span>
                <span className="text-low font-normal">
                  #{pullRequest.number}
                </span>
              </span>
            ) : (
              <>#{pullRequest.number}</>
            )}
          </Link>
        )}
      </Button>
    </Tooltip>
  );
};