import AuthContext from "../../store/auth-context";
import React, { useContext } from "react";

const ProfileForm = () => {
  const authCtx = useContext(AuthContext);

  return (
    <React.Fragment>
      <h1>Your access token</h1>
      <p>{authCtx.token}</p>
    </React.Fragment>
  );
};

export default ProfileForm;
