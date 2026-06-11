import { Suspense } from "react";
import { AssetsView } from "@/components/assets-view";
import { LoadingState } from "@/components/states";

// AssetsView reads useSearchParams() (topbar search pushes /assets?q=…), so
// Next requires a Suspense boundary around it for prerendering.
export default function Page() {
  return (
    <Suspense fallback={<LoadingState />}>
      <AssetsView />
    </Suspense>
  );
}
