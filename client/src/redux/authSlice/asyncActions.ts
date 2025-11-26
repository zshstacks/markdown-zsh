import { createAsyncThunk } from "@reduxjs/toolkit";

import api from "@/redux/api";

export const registerUser = createAsyncThunk(
  "auth/registerUser",
  async (
    userData: { email: string; password: string; username: string },
    thunkAPI,
  ) => {
    try {
      const res = await api.post("/register", userData);
      return res.data;
    } catch (error) {
      return thunkAPI.rejectWithValue("Register failed");
    }
  },
);

export const loginUser = createAsyncThunk(
  "auth/loginUser",
  async (userData: { email: string; password: string }, thunkAPI) => {
    try {
      const res = await api.post("/login", userData);
      return res.data;
    } catch (error) {
      return thunkAPI.rejectWithValue("Login failed");
    }
  },
);
