import { clsx } from "clsx";
import { forwardRef } from "react";

export const ImageAvatar = forwardRef<
  HTMLImageElement,
  {
    className?: string;
    size?: number;
    url: string;
  }
>((props, ref) => {
  const size = props.size ?? 32;
  return (
    <img
      ref={ref}
      src={props.url}
      alt=""
      className={clsx(props.className, "rounded-full")}
      height={size}
      width={size}
    />
  );
});
