"use client";
import { AuthWrapper } from "@/features/auth";

export default function Page() {
  return (
    <AuthWrapper>
      <div className="text-9xl text-black font-bold  flex justify-center text-center align-middle">
        Main Content
      </div>
    </AuthWrapper>
  );
}
