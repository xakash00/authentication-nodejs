import * as dotenv from "dotenv";
import { PathLike } from "fs";

dotenv.config();

interface Config {
    PORT: number | String;
    DATA_FILE: PathLike;
    MONGODB_URI: string,
    SALT_ROUNDS: number,
    JWT_SECRET: string,
    JWT_EXPIRES_IN: string,
    JWT_REFRESH_EXPRIRES_IN: string
}

export const config: Config = {
    PORT: process.env.PORT || 4000,
    DATA_FILE: '../blog.json',
    MONGODB_URI: process.env.MONGODB_URI as string,
    SALT_ROUNDS: 12,
    JWT_SECRET: process.env.JWT_SECRET as string,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN as string,
    JWT_REFRESH_EXPRIRES_IN: process.env.JWT_REFRESH_EXPRIRES_IN as string

}
