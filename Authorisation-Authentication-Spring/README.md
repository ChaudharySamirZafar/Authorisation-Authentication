# Authentication-AuthorisationAPI

### Purpose of this project
I wanted to understand the process of Authentication & Authorisation.

### Breakdown
(I am presuming you have some familarity with creating APIs so certain packages will not be talked about & this is my understanding of the code, if you see a mistake don't hesitate to contact me!) <br/>
<br/>
SecurityConfig (In Security Package) : This code is ran when the API starts. We have allowed CORS, this will allow us to send requests from our react applications ( assuming your react application is hosted on localhost:3000). We then make certain requests available to everyone and others exclusive to certain roles. We state that every request should be authenticated.<br/>
<br/>
We then add a custom filter for Authentication, this custom filter will run when we try to log in on our UI.
<br/>
We also add a Authorisation filter, this will run on every request.
<br/>
I will not explain the fitlers as they are accustomed to my needs.

### Important Notes
- The access tokens run out after every ten minutes
- Refresh tokens have not been added. They will be added in the next commit.
- JWT is used for the access token
- passwords are encrypted
- if you try to access a endpoint that you don't have the correct permissions for you'll receive a 403 status code.
- React UI code - https://github.com/ChaudharySamirZafar/ReactAuthenticationApplication

### Contact me
email : Chaudharysamirzafar@gmail.com
linkedin : https://www.linkedin.com/in/samir-zafar-6b59111bb/
