import requests
import json

def get_weather(lat, lon):
    url = f"https://api.open-meteo.com/v1/forecast"
    params = {
        "latitude": lat,
        "longitude": lon,
        "current_weather": "true"
    }
    response = requests.get(url, params=params)
    data = response.json()
    return data

def get_lat_lon(city_name):
    url = "https://geocoding-api.open-meteo.com/v1/search"
    params = {
        "name": city_name
    }
    response = requests.get(url, params=params)
    data = response.json()
    lat_lon_response = {'latitude': data['results'][0]['latitude'], 'longitude': data['results'][0]['longitude']}
    return lat_lon_response 

def get_weather_forecast(lat, lon, forcast_days):
    url = f"https://api.open-meteo.com/v1/forecast"
    params = {
        "latitude": lat,
        "longitude": lon,
        "daily": "temperature_2m_max,temperature_2m_min,precipitation_sum",
        "timezone": "auto",
        "forecast_days": forcast_days
    }
    response = requests.get(url, params=params)
    data = response.json()
    return data 


if __name__ == "__main__":
    # Example usage
    city = "New York"
    lat_lon = get_lat_lon(city)
    print(f"Latitude and Longitude of {city}: {lat_lon}")

    weather = get_weather(lat_lon['latitude'], lat_lon['longitude'])
    print(f"Current weather in {city}: {weather}")

    forecast = get_weather_forecast(lat_lon['latitude'], lat_lon['longitude'], 3)
    print(f"Weather forecast in {city}: {forecast}")
    