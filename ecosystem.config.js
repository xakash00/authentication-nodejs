module.exports = {
    apps: [
        {
            name: 'users-auth',
            script: 'dist/app.js',
            watch: false,
            env: {
                NODE_ENV: 'production',
            },
        },
    ],
};
