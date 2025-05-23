import axios from "axios";
import { Request, Response } from "express";

export const getHomePage = async (req: Request, res: Response) => {
    res.render("index")
}


export const getProducts = async (req: Request, res: Response) => {
    try {
        const response = await axios.get('https://fakestoreapi.com/products');
        res.json({
            success: true,
            data: response.data,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to fetch products',
            error: (error as Error).message,
        });
    }
};