import axios from "axios";
export class TinybirdClient {
    constructor(token, baseUrl = "https://api.europe-west2.gcp.tinybird.co") {
        this.token = token;
        this.baseUrl = baseUrl;
    }
    async query(pipeName, params = {}) {
        const url = `${this.baseUrl}/v0/pipes/${pipeName}.json`;
        try {
            const response = await axios.get(url, {
                headers: {
                    Authorization: `Bearer ${this.token}`,
                },
                params,
            });
            return response.data;
        }
        catch (error) {
            if (axios.isAxiosError(error)) {
                throw new Error(`Tinybird API error: ${error.response?.data?.error || error.message}`);
            }
            throw error;
        }
    }
}
