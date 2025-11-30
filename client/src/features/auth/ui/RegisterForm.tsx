"use client";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import Link from "next/link";
import { useState } from "react";
import { AppDispatch, RootState } from "@/redux/store";
import { useDispatch, useSelector } from "react-redux";
import { registerUser } from "@/redux/authSlice/asyncActions";
import { useRouter } from "next/navigation";
import { clearAuthErrors } from "@/redux/authSlice/authSlice";

interface ValidateErrors {
  password?: string;
  "confirm-password"?: string;

  [key: string]: string | undefined;
}

function RegisterForm({ ...props }: React.ComponentProps<typeof Card>) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [validateErrors, setValidateErrors] = useState<ValidateErrors>({});
  const [isFormSubmitting, setIsFormSubmitting] = useState(false);

  const dispatch: AppDispatch = useDispatch();
  const auth = useSelector((state: RootState) => state.auth);

  const router = useRouter();

  const clearForm = () => {
    setUsername("");
    setEmail("");
    setPassword("");
    setConfirmPassword("");
    setValidateErrors({});
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (validateErrors[e.target.name]) {
      setValidateErrors((prev) => {
        const newErrors = { ...prev };
        delete newErrors[e.target.name];
        return newErrors;
      });
    }

    switch (e.target.name) {
      case "username":
        setUsername(e.target.value);
        break;
      case "email":
        setEmail(e.target.value);
        break;
      case "password":
        setPassword(e.target.value);
        break;
      case "confirm-password":
        setConfirmPassword(e.target.value);
      default:
        break;
    }

    dispatch(clearAuthErrors());
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    setIsFormSubmitting(true);

    if (password !== confirmPassword) {
      setValidateErrors({
        password: "Passwords do not match",
        "confirm-password": "Passwords do not match",
      });
      setIsFormSubmitting(false);
      return;
    }

    if (password.length < 8) {
      setValidateErrors({
        password: "Password must be at least 8 characters",
      });
      setIsFormSubmitting(false);
      return;
    }

    setValidateErrors({});

    const userData = { email, password, username };
    const result = await dispatch(registerUser(userData));

    if (result.type === "auth/registerUser/fulfilled") {
      clearForm();
      router.push("/login");
      setIsFormSubmitting(false);
    } else {
      console.log("Register error: ", result.payload);
      setIsFormSubmitting(false);
    }
  };

  const passwordError = validateErrors.password;
  const confirmPasswordError = validateErrors["confirm-password"];
  const globalError = auth.error;

  return (
    <Card {...props}>
      <CardHeader>
        <CardTitle>Create an account</CardTitle>
        <CardDescription>
          Enter your information below to create your account
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="username">Displayed name</FieldLabel>
              <Input
                id="username"
                name="username"
                value={username}
                onChange={handleInputChange}
                type="text"
                placeholder="John Doe"
                isInvalid={!!validateErrors.username}
                required
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="email">Email</FieldLabel>
              <Input
                id="email"
                name="email"
                value={email}
                onChange={handleInputChange}
                type="email"
                placeholder="m@example.com"
                required
                isInvalid={!!validateErrors.email}
              />
              <FieldDescription>
                We&apos;ll use this to contact you. We will not share your email
                with anyone else.
              </FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="password">Password</FieldLabel>
              <Input
                id="password"
                name="password"
                value={password}
                onChange={handleInputChange}
                type="password"
                isInvalid={!!passwordError}
                required
              />
              {passwordError ? (
                <FieldDescription className="text-red-600">
                  {passwordError}
                </FieldDescription>
              ) : (
                <FieldDescription
                  className={`${passwordError ? "text-red-600" : ""}`}
                >
                  Must be at least 8 characters long.
                </FieldDescription>
              )}
            </Field>
            <Field>
              <FieldLabel htmlFor="confirm-password">
                Confirm Password
              </FieldLabel>
              <Input
                id="confirm-password"
                name="confirm-password"
                value={confirmPassword}
                onChange={handleInputChange}
                type="password"
                isInvalid={!!confirmPasswordError}
                required
              />
              {confirmPasswordError ? (
                <FieldDescription className="text-red-600">
                  {confirmPasswordError}
                </FieldDescription>
              ) : (
                <FieldDescription>
                  Please confirm your password.
                </FieldDescription>
              )}
            </Field>
            <FieldGroup>
              <Field>
                {globalError && (
                  <FieldDescription className="text-red-600 ">
                    {globalError}
                  </FieldDescription>
                )}

                <Button
                  type="submit"
                  disabled={isFormSubmitting}
                  className="cursor-pointer"
                >
                  {isFormSubmitting ? "Creating Account..." : "Create Account"}
                </Button>

                <FieldDescription className="px-6 text-center">
                  Already have an account? <Link href="/login">Sign in</Link>
                </FieldDescription>
              </Field>
            </FieldGroup>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  );
}

export default RegisterForm;
