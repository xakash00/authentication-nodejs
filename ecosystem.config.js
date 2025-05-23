module.exports = {
    apps: [
        {
            name: 'blogs-crud',
            script: 'dist/app.js',
            watch: false,
            env: {
                NODE_ENV: 'production',
            },
        },
    ],
};
