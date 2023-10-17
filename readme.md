# Node TypeScript Starter Template for Backend Development

![Node.js](https://img.shields.io/badge/Node.js-18.x-green)
![TypeScript](https://img.shields.io/badge/TypeScript-4.x-blue)
![Redis](https://img.shields.io/badge/Redis-6.x-red)

Get started with backend development using Node.js and TypeScript. This starter template includes authentication, user, and admin APIs to kickstart your project.

## Technologies

-   Node
-   Typescript
-   Express
-   Mongoose
-   Redis

## Linters

-   Eslint
-   Prettier

## Prerequisites

Before you begin, ensure you have met the following requirements:

-   [Node.js](https://nodejs.org/) (18.x or higher) installed on your system.
-   [Redis](https://redis.io/) (6.x or higher) installed and running on your system.
-   Clone or download this repository to your local machine.
-   A code editor of your choice, like Visual Studio Code.

## Setup

1.  Clone the repository to your local machine:

    ```bash
    git clone https://github.com/Lekejosh/my-node-typescript-template.git
    cd my-node-typescript-template
    ```

2.  Install the project dependencies using [npm](https://www.npmjs.com/):

    ```bash
    npm install
    ```

3.  Create a `.env` file in the project root and add the following environment variables example in the .env.sample file

4.  Start the development server:

```bash
npm run watch (run this in one terminal in the project directory)
npm run dev (this in another terminal in the project directory)
```

## APIs

-   **Authentication**: Secure user registration, login, and JWT token generation.
-   **User**: Manage user profiles, update information, and view user details.
-   **Admin**: Admin-only endpoints for managing the application.

## Postman Collection

You can find a Postman collection for testing the APIs in the `postman` directory within this repository. Import the collection into Postman for easy API testing.

## Contributing

Contributions are welcome! Feel free to submit issues, create pull requests, or open discussions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Happy Coding!** 🚀
