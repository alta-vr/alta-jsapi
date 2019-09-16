export default function createLogger(name:string, level:number)
{
    var result = {
        info : (value:any) => {},
        warn : (value:any) => {},
        error : (value:any) => {}
    };

    if (level >= 0)
    {
        result.error = (value:any) => console.error(`[${name}] ${value}`);
    }

    if (level >= 1)
    {
        result.warn = (value:any) => console.warn(`[${name}] ${value}`);
    }

    if (level >= 2)
    {
        result.info = (value:any) => console.log(`[${name}] ${value}`);
    }

    return result;
}