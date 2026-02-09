from mcp.server.fastmcp import FastMCP
import weather_api as wapi

mcp = FastMCP(name="HttpWeatherServer")

# @mcp.tool()
# def greet(name: str) -> str:
#     """Greet a user by name."""
#     return f"Hello, {name}!"

@mcp.tool()
def get_current_weather(city_name: str, state_name: str, country: str) -> dict:
    lat_lon = wapi.get_lat_lon(city_name)
    weather_data = wapi.get_weather(lat_lon['latitude'], lat_lon['longitude'])
    return weather_data

@mcp.tool()
def get_weather_forecast(city_name: str, state_name: str, country: str, forcast_days: int) -> dict:
    lat_lon = wapi.get_lat_lon(city_name)
    forecast_data = wapi.get_weather_forecast(lat_lon['latitude'], lat_lon['longitude'], forcast_days)
    return forecast_data


if __name__ == "__main__":
    # Defaults to STDIO transport
    # mcp.run()

    # Or use HTTP transport
    mcp.run(transport="streamable-http")
