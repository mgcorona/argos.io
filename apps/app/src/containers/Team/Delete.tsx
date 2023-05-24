import { useApolloClient } from "@apollo/client";
import { FormProvider, SubmitHandler, useForm } from "react-hook-form";

import { FragmentType, graphql, useFragment } from "@/gql";
import { PurchaseStatus } from "@/gql/graphql";
import { Button, ButtonProps } from "@/ui/Button";
import {
  Card,
  CardBody,
  CardFooter,
  CardParagraph,
  CardTitle,
} from "@/ui/Card";
import {
  Dialog,
  DialogBody,
  DialogDisclosure,
  DialogDismiss,
  DialogFooter,
  DialogText,
  DialogTitle,
  useDialogState,
} from "@/ui/Dialog";
import { Form } from "@/ui/Form";
import { FormSubmit } from "@/ui/FormSubmit";
import { FormTextInput } from "@/ui/FormTextInput";
import { MagicTooltip } from "@/ui/Tooltip";

const TeamFragment = graphql(`
  fragment TeamDelete_Team on Team {
    id
    slug
    purchaseStatus
    pendingCancelAt
  }
`);

type ConfirmDeleteInputs = {
  name: string;
  verify: string;
};

const DeleteTeamMutation = graphql(`
  mutation DeleteTeamMutation($teamAccountId: ID!) {
    deleteTeam(input: { accountId: $teamAccountId })
  }
`);

const DeleteButton = (props: Omit<ButtonProps, "color">) => {
  return (
    <Button color="danger" {...props}>
      Delete
    </Button>
  );
};

type DeleteTeamButtonProps = {
  teamAccountId: string;
  teamSlug: string;
};

const DeleteTeamButton = (props: DeleteTeamButtonProps) => {
  const dialog = useDialogState();
  const client = useApolloClient();
  const form = useForm<ConfirmDeleteInputs>({
    defaultValues: {
      name: "",
      verify: "",
    },
  });
  const onSubmit: SubmitHandler<ConfirmDeleteInputs> = async () => {
    await client.mutate({
      mutation: DeleteTeamMutation,
      variables: {
        teamAccountId: props.teamAccountId,
      },
    });
    window.location.replace(`/`);
  };
  return (
    <>
      <DialogDisclosure state={dialog}>
        {(disclosureProps) => <DeleteButton {...disclosureProps} />}
      </DialogDisclosure>
      <Dialog state={dialog} style={{ width: 560 }}>
        <FormProvider {...form}>
          <Form onSubmit={onSubmit}>
            <DialogBody>
              <DialogTitle>Delete Team</DialogTitle>
              <DialogText>
                Argos will delete all of your Team's projects, along with all of
                its Builds, Screenshots, Screenshot Diffs, Settings and other
                resources belonging to your Team.
              </DialogText>
              <DialogText>
                Argos recommends that you transfer projects you want to keep to
                another Team before deleting this Team.
              </DialogText>
              <div className="my-8 rounded bg-danger-600 p-2">
                <strong>Warning:</strong> This action is not reversible. Please
                be certain.
              </div>
              <FormTextInput
                {...form.register("name", {
                  validate: (value) => {
                    if (value !== props.teamSlug) {
                      return "Team name does not match";
                    }
                    return true;
                  },
                })}
                className="mb-4"
                label={
                  <>
                    Enter the team name <strong>{props.teamSlug}</strong> to
                    continue:
                  </>
                }
              />
              <FormTextInput
                {...form.register("verify", {
                  validate: (value) => {
                    if (value !== "delete my team") {
                      return "Please type 'delete my team' to confirm";
                    }
                    return true;
                  },
                })}
                label={
                  <>
                    To verify, type <strong>delete my team</strong> below:
                  </>
                }
              />
            </DialogBody>
            <DialogFooter>
              <DialogDismiss>Cancel</DialogDismiss>
              <FormSubmit color="danger">Delete</FormSubmit>
            </DialogFooter>
          </Form>
        </FormProvider>
      </Dialog>
    </>
  );
};

export const TeamDelete = (props: {
  team: FragmentType<typeof TeamFragment>;
}) => {
  const team = useFragment(TeamFragment, props.team);
  const hasActivePurchase =
    team.purchaseStatus === PurchaseStatus.Active &&
    team.pendingCancelAt === null;
  return (
    <Card intent="danger">
      <CardBody>
        <CardTitle>Delete Team</CardTitle>
        <CardParagraph>
          Permanently remove your Team and all of its contents from the Argos
          platform. This action is not reversible — please continue with
          caution.
        </CardParagraph>
      </CardBody>
      {hasActivePurchase ? (
        <CardFooter className="flex items-center justify-between">
          <div>
            A purchase is active on the team. Please cancel your purchase before
            deleting the team.
          </div>
          <MagicTooltip tooltip="Cancel your purchase before deleting the team.">
            <DeleteButton disabled accessibleWhenDisabled />
          </MagicTooltip>
        </CardFooter>
      ) : (
        <CardFooter className="flex items-center justify-end">
          <DeleteTeamButton teamAccountId={team.id} teamSlug={team.slug} />
        </CardFooter>
      )}
    </Card>
  );
};
