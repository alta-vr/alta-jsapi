export default function createLogger(name: string, level: number): {
    info: (value: any) => void;
    warn: (value: any) => void;
    error: (value: any) => void;
};
