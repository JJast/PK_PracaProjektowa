import React, { useState } from "react";
import "../styles/forms.css";
import { API_BASE_URL } from "../utils/constants";
import toast from "react-hot-toast";
import { useForm, type SubmitHandler } from "react-hook-form"

type RegistrationInputs = {
  email: string
  password: string
}

const testPassword = (value: string) => {
  if (!/[A-Z]/.test(value)) return "Your password needs to include an uppercase letter";
  if (!/[a-z]/.test(value)) return "Your password needs to include a lowercase letter";
  if (!/\d/.test(value)) return "Your password needs to include a digit";
  if (!/[^A-Za-z0-9]/.test(value)) return "Your password needs to include a special character";

  return true
}

const SignUpForm: React.FC = () => {
  const [loading, setLoading] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<RegistrationInputs>({
    mode: 'all',
  })

  const onSubmit: SubmitHandler<RegistrationInputs> = async (data) => {
    const { email, password } = data;

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username: email, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        toast.error(data.error || "Registration failed");
      } else {
        toast.success("Registered successfully.\nYou can now sign in.");
        // If server returns a 'next' endpoint (webauthn), fetch its options to verify the flow
        if (data.next) {
          const optsRes = await fetch(`${API_BASE_URL}${data.next}`, {
            method: "GET",
            credentials: "include",
          });
          const opts = await optsRes.json();
          console.log("WebAuthn options:", opts);
        }
      }
    } catch (err) {
      toast.error(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-container sign-up">
      <form onSubmit={handleSubmit(onSubmit)}>
        <h1>Create Account</h1>
        <label htmlFor="register-email" style={{ alignSelf: "start" }}>E-mail address</label>
        <input
          type="email"
          placeholder="example@company.org"
          id="register-email"

          {...register("email", {
            required: true,
            pattern: {
              value: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
              message: "Please enter a valid e-mail address."
            }
          })}
        />
        <div className="error-container">
          {errors.email && <span>{errors.email.message}</span>}
        </div>
        <label htmlFor="register-password" style={{ alignSelf: "start" }}>Password</label>
        <input
          type="password"
          placeholder="********"
          autoComplete="off"
          id="register-password"

          {...register("password", {
            minLength: { value: 8, message: "Password length needs to be at least 8 characters" },
            required: true,
            validate: {
              checkComplexity: testPassword
            }
          })}
        />
        <div className="error-container">
          {errors.password && <span>{errors.password.message}</span>}
        </div>
        <button type="submit" disabled={loading || !!errors.email || !!errors.password}>
          {loading ? "Signing up..." : "Sign Up"}
        </button>
      </form>
    </div>
  );
};

export default SignUpForm;
