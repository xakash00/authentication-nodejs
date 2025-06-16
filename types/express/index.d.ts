// types/express/index.d.ts
import { IUser } from '../../src/models/AuthModels';

declare global {
    namespace Express {
        interface Request {
            user?: UserDocument;
            token?: string;
        }
    }
}


