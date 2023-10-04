import { ExternalLinkIcon } from "lucide-react";

import config from "@/config";
import { FragmentType, graphql, useFragment } from "@/gql";
import { Button, ButtonIcon } from "@/ui/Button";
import { Card, CardBody, CardParagraph, CardTitle } from "@/ui/Card";
import { VercelLogo } from "@/ui/VercelLogo";

const AccountFragment = graphql(`
  fragment AccountVercel_Account on Account {
    id
    vercelConfiguration {
      id
      url
    }
  }
`);

export const AccountVercel = (props: {
  account: FragmentType<typeof AccountFragment>;
}) => {
  const account = useFragment(AccountFragment, props.account);
  return (
    <Card>
      <CardBody>
        <CardTitle>Vercel Integration</CardTitle>
        <CardParagraph>
          Connect your account to Vercel to link your projects.
        </CardParagraph>
        {account.vercelConfiguration ? (
          <div className="flex items-center gap-2 rounded border p-4">
            <VercelLogo height={24} />
            <div className="flex-1 font-semibold">
              <a
                className="text no-underline hover:underline"
                href={account.vercelConfiguration.url}
                target="_blank"
                rel="noopener noreferrer"
              >
                Manage on Vercel{" "}
                <ExternalLinkIcon className="inline h-[1em] w-[1em] mb-0.5" />
              </a>
            </div>
          </div>
        ) : (
          <Button color="neutral">
            {(buttonProps) => (
              <a
                href={config.get("vercel.integrationUrl")}
                target="_blank"
                rel="noopener noreferrer"
                {...buttonProps}
              >
                <ButtonIcon>
                  <VercelLogo />
                </ButtonIcon>
                Vercel Marketplace
              </a>
            )}
          </Button>
        )}
      </CardBody>
    </Card>
  );
};