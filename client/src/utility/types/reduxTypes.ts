interface UserType {
  id: number;
  uniqueID: string;
  email: string;
  username: string;
  createdAt: Date;
}

export interface AuthState {
  user: UserType | null;
  error: string | null;
  isLoading: boolean;
}
