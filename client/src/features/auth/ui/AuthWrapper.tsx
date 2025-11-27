"use client";

import { ReactNode, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "@/redux/store";
import { loadUser } from "@/redux/authSlice/asyncActions";
import { SpinnerCustom } from "@/components/ui/spinner";

function AuthWrapper({ children }: { children: ReactNode }) {
  const auth = useSelector((state: RootState) => state.auth);
  const router = useRouter();
  const dispatch: AppDispatch = useDispatch();

  useEffect(() => {
    const fetchData = async () => {
      await dispatch(loadUser());
    };
    fetchData();
  }, []);

  if (auth.isLoading) {
    return (
      <div className=" flex font-black min-h-screen justify-center text-center">
        <SpinnerCustom className="size-8" />
      </div>
    );
  }

  if (auth.user === null) {
    router.push("/login");
    return null;
  }

  return <div>{children}</div>;
}

export default AuthWrapper;
